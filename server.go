package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type options struct {
	address, profile   string
	allowIMDS, version bool
}

func parseOptions(args []string, output io.Writer) (options, error) {
	var opts options
	flags := flag.NewFlagSet("imds-credential-server", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.address, "listen", "127.0.0.1:9911", "listen address, defaults to loopback")
	legacyPort := flags.String("port", "", "legacy [HOST:]PORT alias for --listen")
	flags.StringVar(&opts.profile, "profile", "", "optional AWS profile, otherwise use the default credential chain")
	flags.BoolVar(&opts.allowIMDS, "allow-imds", false, "allow EC2 metadata as an upstream credential source")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() == 1 && flags.Arg(0) == "version" {
		opts.version = true
		return opts, nil
	}
	listenSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			listenSet = true
		}
	})
	if flags.NArg() > 1 || (flags.NArg() == 1 && (*legacyPort != "" || listenSet)) || (*legacyPort != "" && listenSet) {
		return opts, errors.New("provide only one listen address")
	}
	if *legacyPort != "" {
		opts.address = *legacyPort
	}
	if flags.NArg() == 1 {
		opts.address = flags.Arg(0)
	}
	address, err := normalizeAddress(opts.address)
	if err != nil {
		return opts, err
	}
	opts.address = address
	return opts, nil
}

func normalizeAddress(value string) (string, error) {
	if _, err := strconv.Atoi(value); err == nil {
		value = "127.0.0.1:" + value
	}
	if strings.HasPrefix(value, ":") {
		value = "127.0.0.1" + value
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("invalid listen address: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", errors.New("invalid listen port")
	}
	return value, nil
}

func newHTTPServer(address string, cfg *Config) *http.Server {
	return &http.Server{
		Addr: address, Handler: cfg,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: cfg.credentialTimeout() + 5*time.Second,
		IdleTimeout:  time.Minute, MaxHeaderBytes: 8 << 10,
	}
}

func serve(ctx context.Context, server *http.Server, listener net.Listener, shutdownTimeout time.Duration) error {
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("HTTP shutdown: %w", err)
		}
		err := <-result
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func checkHealth(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	flags.SetOutput(output)
	endpoint := flags.String("url", "http://127.0.0.1:9911/readyz", "health or readiness endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("healthcheck does not accept positional arguments")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *endpoint, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("health endpoint is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "healthcheck" {
		err := checkHealth(ctx, args[1:], stderr)
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if opts.version {
		_, err := fmt.Fprintln(stdout, Version)
		return err
	}
	startupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	awsCfg, err := loadAWSConfig(startupCtx, opts.profile, opts.allowIMDS, defaultCredentialTimeout)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	cfg, err := NewConfig(startupCtx, awsCfg, defaultCredentialTimeout)
	if err != nil {
		// Credential-process and upstream errors can contain credential material.
		return errors.New("AWS startup validation failed; check credentials, workload identity and region")
	}
	cancel()
	listener, err := net.Listen("tcp", opts.address)
	if err != nil {
		return err
	}
	defer listener.Close()
	_, _ = fmt.Fprintf(stderr, "serving IMDS on %s\n", listener.Addr())
	return serve(ctx, newHTTPServer(opts.address, cfg), listener, 10*time.Second)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
