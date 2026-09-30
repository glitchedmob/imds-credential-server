package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func isolatedAWS(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY",
		"AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN",
		"AWS_ROLE_SESSION_NAME", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
	} {
		t.Setenv(name, "")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_REGION", "us-east-2")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-2")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
}

func TestIMDSFallbackDisabled(t *testing.T) {
	isolatedAWS(t)
	var requests atomic.Int32
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer metadata.Close()
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", metadata.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cfg, err := loadAWSConfig(ctx, "", false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err == nil {
		t.Fatal("found unexpected credentials")
	}
	if requests.Load() != 0 {
		t.Fatal("contacted metadata despite disabled fallback")
	}
}

func TestWebIdentityRotationThroughIMDS(t *testing.T) {
	isolatedAWS(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("synthetic-token-one"), 0600); err != nil {
		t.Fatal(err)
	}
	mockSTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "AssumeRoleWithWebIdentity":
			key := map[string]string{"synthetic-token-one": "synthetic-key-one", "synthetic-token-two": "synthetic-key-two"}[r.Form.Get("WebIdentityToken")]
			if key == "" {
				t.Error("incorrect projected token")
				w.WriteHeader(400)
				return
			}
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>synthetic-secret</SecretAccessKey><SessionToken>synthetic-session</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, key, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
		case "GetCallerIdentity":
			io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test</Arn><Account>123456789012</Account><UserId>test:test</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		default:
			t.Error("unexpected STS action")
			w.WriteHeader(400)
		}
	}))
	defer mockSTS.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", mockSTS.URL)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/TestRole")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	awsCfg, err := loadAWSConfig(ctx, "", false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig(ctx, awsCfg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token := string(cfg.EncodeToken(time.Hour))
	first := request(cfg, "GET", credentialsPath+"/TestRole", token)
	if first.Code != 200 || !strings.Contains(first.Body.String(), "synthetic-key-one") {
		t.Fatal("first credentials not served")
	}
	if err := os.WriteFile(tokenFile, []byte("synthetic-token-two"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.AwsConfig.Credentials.(*aws.CredentialsCache).Invalidate()
	second := request(cfg, "GET", credentialsPath+"/TestRole", token)
	if second.Code != 200 || !strings.Contains(second.Body.String(), "synthetic-key-two") {
		t.Fatal("projected token was not re-read on refresh")
	}
}

func TestCredentialTimeoutAndReadiness(t *testing.T) {
	cfg := testConfig()
	cfg.RequestTimeout = 20 * time.Millisecond
	cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) { <-ctx.Done(); return aws.Credentials{}, ctx.Err() })
	start := time.Now()
	if request(cfg, "GET", "/readyz", "").Code != 503 || time.Since(start) > time.Second {
		t.Fatal("readiness retrieval was not bounded")
	}
	if request(cfg, "GET", "/healthz", "").Code != 200 {
		t.Fatal("liveness depends on AWS")
	}
}
