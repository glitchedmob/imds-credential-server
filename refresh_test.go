package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestExpiredCacheRefreshes(t *testing.T) {
	var calls atomic.Int32
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		expires := time.Now().Add(-time.Second)
		if calls.Add(1) > 1 {
			expires = time.Now().Add(time.Hour)
		}
		return aws.Credentials{AccessKeyID: "synthetic-key", SecretAccessKey: "synthetic-secret", SessionToken: "synthetic-session", CanExpire: true, Expires: expires}, nil
	})
	cfg := testConfig()
	cfg.AwsConfig.Credentials = aws.NewCredentialsCache(provider)
	if _, err := cfg.GenerateResponse(context.Background()); err == nil {
		t.Fatal("served expired cached credentials")
	}
	if _, err := cfg.GenerateResponse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("expired SDK cache did not refresh")
	}
}

func TestStaticCredentialsAreConvertedAndCached(t *testing.T) {
	isolatedAWS(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-static-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-static-secret")
	var sessionRequests atomic.Int32
	mockSTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "GetCallerIdentity":
			io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/path/TestUser</Arn><Account>123456789012</Account><UserId>test</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case "GetSessionToken":
			if r.Header.Get("X-Amz-Security-Token") != "" {
				t.Error("used converted credentials to request another session")
			}
			sessionRequests.Add(1)
			fmt.Fprintf(w, `<GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetSessionTokenResult><Credentials><AccessKeyId>synthetic-session-key</AccessKeyId><SecretAccessKey>synthetic-session-secret</SecretAccessKey><SessionToken>synthetic-session-token</SessionToken><Expiration>%s</Expiration></Credentials></GetSessionTokenResult></GetSessionTokenResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
		default:
			t.Error("unexpected STS action")
			w.WriteHeader(400)
		}
	}))
	defer mockSTS.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", mockSTS.URL)
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
	if cfg.PrincipalName != "TestUser" {
		t.Fatal("incorrect user name")
	}
	for range 2 {
		response, err := cfg.GenerateResponse(ctx)
		if err != nil || response.AccessKeyId != "synthetic-session-key" || response.Token != "synthetic-session-token" {
			t.Fatal("static credentials were not converted")
		}
	}
	if sessionRequests.Load() != 1 {
		t.Fatal("session credentials were not cached")
	}
	cfg.AwsConfig.Credentials.(*aws.CredentialsCache).Invalidate()
	if _, err := cfg.GenerateResponse(ctx); err != nil {
		t.Fatal(err)
	}
	if sessionRequests.Load() != 2 {
		t.Fatal("session credentials did not refresh")
	}
}
