package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func testConfig() *Config {
	return &Config{
		secret: bytes.Repeat([]byte{1}, 32), PrincipalName: "TestRole",
		AwsConfig: aws.Config{Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID: "test-key", SecretAccessKey: "test-secret", SessionToken: "test-session",
				CanExpire: true, Expires: time.Now().UTC().Add(time.Hour),
			}, nil
		})},
	}
}

func request(cfg *Config, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Aws-Ec2-Metadata-Token", token)
	w := httptest.NewRecorder()
	cfg.ServeHTTP(w, req)
	return w
}

func TestToken(t *testing.T) {
	cfg := testConfig()
	for _, ttl := range []string{"60", "", "0", "21601", "invalid"} {
		req := httptest.NewRequest("PUT", "/latest/api/token", nil)
		req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", ttl)
		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)
		if ttl == "60" {
			if w.Code != 200 || cfg.ValidateToken(w.Body.String()) != nil || w.Header().Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds") != ttl {
				t.Fatal("invalid token response")
			}
		} else if w.Code != 400 {
			t.Fatalf("TTL %q: status %d", ttl, w.Code)
		}
	}
	if cfg.ValidateToken(string(cfg.EncodeToken(-time.Second))) == nil {
		t.Fatal("accepted expired token")
	}
	foreign := testConfig()
	foreign.secret = bytes.Repeat([]byte{2}, 32)
	if cfg.ValidateToken(string(foreign.EncodeToken(time.Hour))) == nil {
		t.Fatal("accepted foreign token")
	}
	req := httptest.NewRequest("PUT", "/latest/api/token", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	w := httptest.NewRecorder()
	cfg.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("accepted forwarded token request")
	}
}

func TestMetadataErrors(t *testing.T) {
	cfg := testConfig()
	token := string(cfg.EncodeToken(time.Hour))
	for _, tc := range []struct {
		method, path, token string
		status              int
	}{
		{"GET", credentialsPath + "/", "", 401},
		{"GET", credentialsPath + "/", "invalid", 401},
		{"POST", credentialsPath + "/", token, 405},
		{"GET", credentialsPath + "/OtherRole", token, 404},
		{"GET", "/other", token, 404},
	} {
		if w := request(cfg, tc.method, tc.path, tc.token); w.Code != tc.status {
			t.Fatalf("%s %s: status %d, want %d", tc.method, tc.path, w.Code, tc.status)
		}
	}
	cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, errors.New("unavailable") })
	if request(cfg, "GET", credentialsPath+"/TestRole", token).Code != 500 {
		t.Fatal("incorrect credential failure status")
	}
}

func TestCredentialResponse(t *testing.T) {
	cfg := testConfig()
	token := string(cfg.EncodeToken(time.Hour))
	if w := request(cfg, http.MethodGet, credentialsPath+"/", token); w.Code != 200 || w.Body.String() != "TestRole" {
		t.Fatal("incorrect role listing")
	}
	w := request(cfg, http.MethodGet, credentialsPath+"/TestRole", token)
	var response Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || response.Code != "Success" || response.AccessKeyId != "test-key" || response.Token != "test-session" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("incorrect credential response")
	}
	if _, err := time.Parse(time.RFC3339Nano, response.Expiration); err != nil {
		t.Fatal(err)
	}
}
