package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestListenOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		address string
	}{
		{"default", nil, "127.0.0.1:9911"},
		{"port", []string{"8081"}, "127.0.0.1:8081"},
		{"legacy", []string{"--port", ":8081"}, "127.0.0.1:8081"},
		{"explicit", []string{"--listen", "0.0.0.0:9911"}, "0.0.0.0:9911"},
		{"ipv6", []string{"--listen", "[::1]:9911"}, "[::1]:9911"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseOptions(tc.args, io.Discard)
			if err != nil || opts.address != tc.address {
				t.Fatalf("got %q, %v", opts.address, err)
			}
			if opts.allowIMDS {
				t.Fatal("IMDS fallback enabled by default")
			}
		})
	}
	for _, args := range [][]string{
		{"bad-address"}, {"--listen", "localhost:99999"}, {"--listen", "localhost:-1"},
		{"--listen", ""}, {"one", "two"}, {"--listen", "127.0.0.1:1", "2"},
		{"--listen", "127.0.0.1:1", "--port", "2"},
		{"--credential-timeout", "0"}, {"--credential-timeout", "2m"},
		{"--startup-timeout", "-1s"}, {"--shutdown-timeout", "0"},
	} {
		if _, err := parseOptions(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid arguments %v", args)
		}
	}
}

func TestVersionAndHelpDoNotLoadAWS(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if out.String() != Version+"\n" {
		t.Fatal("incorrect version")
	}
	if err := run(context.Background(), []string{"--help"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPTimeoutsAndShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := newHTTPServer(listener.Addr().String(), testConfig())
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= defaultCredentialTimeout || server.IdleTimeout <= 0 || server.MaxHeaderBytes > 16384 {
		t.Fatal("unbounded HTTP server")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, server, listener, time.Second) }()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("unhealthy HTTP server")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
	if _, err := client.Get("http://" + listener.Addr().String() + "/healthz"); err == nil {
		t.Fatal("server still accepts requests")
	}
}

func TestHTTPListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if err := serve(context.Background(), newHTTPServer("", testConfig()), listener, time.Second); err == nil {
		t.Fatal("ignored listener failure")
	}
}

func TestHealthcheckCommand(t *testing.T) {
	server := httptest.NewServer(testConfig())
	defer server.Close()
	if err := run(context.Background(), []string{"healthcheck", "--url", server.URL + "/readyz"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"healthcheck", "--url", server.URL + "/missing"}, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted failed healthcheck")
	}
}

func TestStartupFailureIsBounded(t *testing.T) {
	isolatedAWS(t)
	start := time.Now()
	if err := run(context.Background(), []string{"--startup-timeout", "100ms"}, io.Discard, io.Discard); err == nil {
		t.Fatal("started without credentials")
	}
	if time.Since(start) > time.Second {
		t.Fatal("startup failure was not bounded")
	}
	if _, err := NewConfig(context.Background(), aws.Config{}, time.Second); err == nil {
		t.Fatal("accepted missing provider")
	}
	if _, err := NewConfig(context.Background(), testConfig().AwsConfig, 0); err == nil {
		t.Fatal("accepted invalid timeout")
	}
}
