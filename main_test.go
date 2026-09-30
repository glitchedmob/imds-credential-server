package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func testConfig() *Config {
	return &Config{
		secret:        bytes.Repeat([]byte{1}, 32),
		PrincipalArn:  "arn:aws:sts::123456789012:assumed-role/TestRole/test",
		PrincipalName: "TestRole",
		AwsConfig: aws.Config{Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID: "test-access-key", SecretAccessKey: "test-secret-key",
				SessionToken: "test-session-token", CanExpire: true,
				Expires: time.Now().UTC().Add(time.Hour),
			}, nil
		})},
	}
}

func request(cfg *Config, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("X-Aws-Ec2-Metadata-Token", token)
	}
	w := httptest.NewRecorder()
	cfg.ServeHTTP(w, req)
	return w
}

func TestTokenRequest(t *testing.T) {
	for _, tc := range []struct {
		name, method, ttl, forwarded string
		status                       int
	}{
		{"minimum", "PUT", "1", "", 200},
		{"maximum", "PUT", "21600", "", 200},
		{"missing", "PUT", "", "", 400},
		{"zero", "PUT", "0", "", 400},
		{"negative", "PUT", "-1", "", 400},
		{"too long", "PUT", "21601", "", 400},
		{"not integer", "PUT", "1.5", "", 400},
		{"forwarded", "PUT", "60", "192.0.2.1", 403},
		{"wrong method", "GET", "60", "", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			req := httptest.NewRequest(tc.method, "/latest/api/token", nil)
			req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", tc.ttl)
			req.Header.Set("X-Forwarded-For", tc.forwarded)
			w := httptest.NewRecorder()
			cfg.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response may be cached")
			}
			if tc.status == 200 {
				if err := cfg.ValidateToken(w.Body.String()); err != nil {
					t.Fatal(err)
				}
				if w.Header().Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds") != tc.ttl {
					t.Fatal("TTL header not echoed")
				}
			}
			if tc.status == 405 && w.Header().Get("Allow") != "PUT" {
				t.Fatal("missing Allow header")
			}
		})
	}
}

func TestTokenValidation(t *testing.T) {
	cfg := testConfig()
	valid := string(cfg.EncodeToken(time.Hour))
	foreign := testConfig()
	foreign.secret = bytes.Repeat([]byte{2}, 32)
	for name, token := range map[string]string{
		"empty": "", "bad encoding": "%%%.%%%", "too many parts": "a.b.c",
		"oversized":      strings.Repeat("a", 513),
		"expired":        string(cfg.EncodeToken(-time.Second)),
		"tampered":       valid[:len(valid)-4] + "AAAA",
		"foreign server": string(foreign.EncodeToken(time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			if cfg.ValidateToken(token) == nil {
				t.Fatal("accepted invalid token")
			}
		})
	}
	if err := cfg.ValidateToken(valid); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataErrors(t *testing.T) {
	cfg := testConfig()
	token := string(cfg.EncodeToken(time.Hour))
	for _, tc := range []struct {
		name, method, path, token string
		status                    int
	}{
		{"missing token", "GET", credentialsPath + "/", "", 401},
		{"invalid token", "GET", credentialsPath + "/", "invalid", 401},
		{"wrong method", "POST", credentialsPath + "/", token, 405},
		{"unknown role", "GET", credentialsPath + "/OtherRole", token, 404},
		{"nested role", "GET", credentialsPath + "/TestRole/extra", token, 404},
		{"unknown path", "GET", "/other", token, 404},
		{"similar path", "GET", credentialsPath + "-other", token, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(cfg, tc.method, tc.path, tc.token)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			var body errorBody
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code == "" {
				t.Fatal("missing error code")
			}
		})
	}
}

func TestIMDSCredentialRoundTrip(t *testing.T) {
	cfg := testConfig()
	token := string(cfg.EncodeToken(time.Hour))
	for _, path := range []string{credentialsPath, credentialsPath + "/"} {
		w := request(cfg, "GET", path, token)
		if w.Code != 200 || w.Body.String() != "TestRole" {
			t.Fatalf("invalid role listing: %d", w.Code)
		}
	}
	w := request(cfg, "GET", credentialsPath+"/TestRole", token)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var body Response
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "Success" || body.Type != "AWS-HMAC" || body.Token != "test-session-token" || body.AccessKeyId != "test-access-key" || body.SecretAccessKey != "test-secret-key" {
		t.Fatal("incorrect credential response")
	}
	if _, err := time.Parse(time.RFC3339Nano, body.Expiration); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credentials may be cached")
	}
}

func TestCredentialFailure(t *testing.T) {
	cfg := testConfig()
	cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("unavailable")
	})
	w := request(cfg, http.MethodGet, credentialsPath+"/TestRole", string(cfg.EncodeToken(time.Hour)))
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestUnknownRoleDoesNotRetrieveCredentials(t *testing.T) {
	cfg := testConfig()
	cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		t.Fatal("retrieved credentials for an unknown role")
		return aws.Credentials{}, nil
	})
	w := request(cfg, http.MethodGet, credentialsPath+"/OtherRole", string(cfg.EncodeToken(time.Hour)))
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
