package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// All SDK integration tests use synthetic credentials and local STS endpoints.
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
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_REGION", "us-east-2")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-2")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
}

func TestPrincipalName(t *testing.T) {
	for value, want := range map[string]string{
		"arn:aws:sts::123456789012:assumed-role/TestRole/session": "TestRole",
		"arn:aws:iam::123456789012:user/path/test-user":           "test-user",
		"arn:aws:sts::123456789012:federated-user/test-user":      "test-user",
		"invalid": "", "arn:aws:iam::123456789012:root": "",
		"arn:aws:sts::123456789012:assumed-role":          "",
		"arn:aws:sts::123456789012:assumed-role//session": "",
	} {
		t.Run(value, func(t *testing.T) {
			got, err := principalName(value)
			if want == "" {
				if err == nil {
					t.Fatal("accepted invalid identity")
				}
				return
			}
			if err != nil || got != want {
				t.Fatalf("got %q, %v, want %q", got, err, want)
			}
		})
	}
}

func TestIMDSFallbackDisabled(t *testing.T) {
	isolatedAWS(t)
	var requests atomic.Int32
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(500)
	}))
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
	var mu sync.Mutex
	var tokens []string
	var actions []string
	mockSTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		action := r.Form.Get("Action")
		mu.Lock()
		actions = append(actions, action)
		if action == "AssumeRoleWithWebIdentity" {
			tokens = append(tokens, r.Form.Get("WebIdentityToken"))
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "AssumeRoleWithWebIdentity":
			key := "synthetic-key-one"
			if r.Form.Get("WebIdentityToken") == "synthetic-token-two" {
				key = "synthetic-key-two"
			}
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>synthetic-secret</SecretAccessKey><SessionToken>synthetic-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test</Arn><AssumedRoleId>test:test</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, key, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
		case "GetCallerIdentity":
			io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test</Arn><Account>123456789012</Account><UserId>test:test</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		default:
			t.Errorf("unexpected STS action %q", action)
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
	// Invalidating the SDK cache triggers the same provider path as expiry,
	// without waiting an hour. The SDK must re-read the projected token file.
	cache, ok := cfg.AwsConfig.Credentials.(*aws.CredentialsCache)
	if !ok {
		t.Fatal("lost refreshable SDK credential cache")
	}
	cache.Invalidate()
	second := request(cfg, "GET", credentialsPath+"/TestRole", token)
	if second.Code != 200 || !strings.Contains(second.Body.String(), "synthetic-key-two") {
		t.Fatal("rotated credentials not served")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tokens) != 2 || tokens[0] != "synthetic-token-one" || tokens[1] != "synthetic-token-two" {
		t.Fatal("projected token was not re-read")
	}
	for _, action := range actions {
		if action == "GetSessionToken" {
			t.Fatal("upgraded already temporary credentials")
		}
	}
}

type mockSessionToken struct {
	out   *sts.GetSessionTokenOutput
	err   error
	calls int
}

func (m *mockSessionToken) GetSessionToken(context.Context, *sts.GetSessionTokenInput, ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error) {
	m.calls++
	return m.out, m.err
}

func TestSessionTokenProvider(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	valid := &sts.GetSessionTokenOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("synthetic-key"), SecretAccessKey: aws.String("synthetic-secret"),
		SessionToken: aws.String("synthetic-session"), Expiration: &expires,
	}}
	for name, out := range map[string]*sts.GetSessionTokenOutput{
		"nil response": nil, "nil credentials": {}, "missing fields": {Credentials: &ststypes.Credentials{}},
	} {
		t.Run(name, func(t *testing.T) {
			p := &sessionTokenProvider{client: &mockSessionToken{out: out}}
			if _, err := p.Retrieve(context.Background()); err == nil {
				t.Fatal("accepted invalid STS response")
			}
		})
	}
	client := &mockSessionToken{out: valid}
	cache := aws.NewCredentialsCache(&sessionTokenProvider{client: client}, cacheOptions)
	for range 2 {
		creds, err := cache.Retrieve(context.Background())
		if err != nil || !creds.CanExpire || creds.SessionToken != "synthetic-session" {
			t.Fatal("invalid session credentials")
		}
	}
	if client.calls != 1 {
		t.Fatal("session credentials were not cached")
	}
	cache.Invalidate()
	if _, err := cache.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 2 {
		t.Fatal("session credentials did not refresh")
	}
	failure := &sessionTokenProvider{client: &mockSessionToken{err: errors.New("unavailable")}}
	if _, err := failure.Retrieve(context.Background()); err == nil {
		t.Fatal("ignored STS error")
	}
	expires = time.Now().Add(-time.Second)
	if _, err := (&sessionTokenProvider{client: client}).Retrieve(context.Background()); err == nil {
		t.Fatal("accepted expired session credentials")
	}
}

func TestCredentialTimeoutAndReadiness(t *testing.T) {
	cfg := testConfig()
	cfg.RequestTimeout = 20 * time.Millisecond
	cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		<-ctx.Done()
		return aws.Credentials{}, ctx.Err()
	})
	start := time.Now()
	w := request(cfg, "GET", "/readyz", "")
	if w.Code != 503 || time.Since(start) > time.Second {
		t.Fatal("readiness retrieval was not bounded")
	}
	if request(cfg, "GET", "/healthz", "").Code != 200 {
		t.Fatal("liveness depends on AWS")
	}
	if request(cfg, "POST", "/healthz", "").Code != 405 {
		t.Fatal("health endpoint allowed POST")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cfg.GenerateResponse(cancelled); err == nil {
		t.Fatal("ignored request cancellation")
	}
}

func TestExpiredAndIncompleteCredentials(t *testing.T) {
	for name, creds := range map[string]aws.Credentials{
		"empty":          {},
		"expired":        {AccessKeyID: "test", SecretAccessKey: "test", SessionToken: "test", CanExpire: true, Expires: time.Now().Add(-time.Second)},
		"missing expiry": {AccessKeyID: "test", SecretAccessKey: "test", SessionToken: "test", CanExpire: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return creds, nil })
			if request(cfg, "GET", "/readyz", "").Code != 503 {
				t.Fatal("invalid credentials reported ready")
			}
			if _, err := cfg.GenerateResponse(context.Background()); err == nil {
				t.Fatal("served invalid credentials")
			}
		})
	}
}

func TestCredentialErrorsDoNotLeak(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	cfg := testConfig()
	cfg.AwsConfig.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("synthetic-secret-that-must-not-leak")
	})
	w := request(cfg, "GET", credentialsPath+"/TestRole", string(cfg.EncodeToken(time.Hour)))
	if w.Code != 500 || strings.Contains(w.Body.String()+logs.String(), "synthetic-secret-that-must-not-leak") {
		t.Fatal("credential error leaked")
	}
}
