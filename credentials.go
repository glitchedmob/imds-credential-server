package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultCredentialTimeout = 10 * time.Second

// The server must not ask itself for credentials through IMDS. Workload identity,
// profiles, environment credentials and container credentials remain supported.
func loadAWSConfig(ctx context.Context, profile string, allowIMDS bool, timeout time.Duration) (aws.Config, error) {
	state := imds.ClientDisabled
	if allowIMDS {
		state = imds.ClientEnabled
	}
	opts := []func(*config.LoadOptions) error{
		config.WithEC2IMDSClientEnableState(state),
		config.WithHTTPClient(&http.Client{Timeout: timeout}),
		config.WithCredentialsCacheOptions(cacheOptions),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	return config.LoadDefaultConfig(ctx, opts...)
}

func cacheOptions(opts *aws.CredentialsCacheOptions) {
	opts.ExpiryWindow = time.Minute
	opts.ExpiryWindowJitterFrac = 0.2
}

func NewConfig(ctx context.Context, awsCfg aws.Config, timeout time.Duration) (*Config, error) {
	if awsCfg.Credentials == nil {
		return nil, errors.New("missing AWS credential provider")
	}
	if timeout <= 0 {
		return nil, errors.New("credential timeout must be positive")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate token signing key: %w", err)
	}
	client := sts.NewFromConfig(awsCfg)
	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("resolve caller identity: %w", err)
	}
	if identity == nil || identity.Arn == nil {
		return nil, errors.New("caller identity has no ARN")
	}
	name, err := principalName(*identity.Arn)
	if err != nil {
		return nil, err
	}
	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieve startup credentials: %w", err)
	}
	if creds.SessionToken == "" {
		// Keep the original static provider on the STS client. Cache and refresh
		// its temporary session credentials instead of calling STS per request.
		awsCfg.Credentials = aws.NewCredentialsCache(&sessionTokenProvider{client: client}, cacheOptions)
	}
	cfg := &Config{
		secret: secret, AwsConfig: awsCfg, PrincipalArn: *identity.Arn,
		PrincipalName: name, RequestTimeout: timeout,
	}
	if _, err := cfg.retrieveCredentials(ctx); err != nil {
		return nil, fmt.Errorf("validate startup credentials: %w", err)
	}
	return cfg, nil
}

func principalName(value string) (string, error) {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.AccountID == "" {
		return "", errors.New("invalid caller identity ARN")
	}
	parts := strings.Split(parsed.Resource, "/")
	if parsed.Service == "sts" && len(parts) == 3 && parts[0] == "assumed-role" && parts[1] != "" && parts[2] != "" {
		return parts[1], nil
	}
	if (parsed.Service == "iam" && len(parts) >= 2 && parts[0] == "user") || (parsed.Service == "sts" && len(parts) == 2 && parts[0] == "federated-user") {
		name := parts[len(parts)-1]
		if name != "" {
			return name, nil
		}
	}
	return "", errors.New("unsupported caller identity ARN")
}

func (cfg *Config) credentialTimeout() time.Duration {
	if cfg.RequestTimeout > 0 {
		return cfg.RequestTimeout
	}
	return defaultCredentialTimeout
}

func (cfg *Config) retrieveCredentials(ctx context.Context) (aws.Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.credentialTimeout())
	defer cancel()
	if cfg.AwsConfig.Credentials == nil {
		return aws.Credentials{}, errors.New("missing credential provider")
	}
	creds, err := cfg.AwsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return aws.Credentials{}, errors.New("incomplete temporary credentials")
	}
	if (creds.CanExpire && creds.Expires.IsZero()) || (!creds.Expires.IsZero() && !creds.Expires.After(time.Now())) {
		return aws.Credentials{}, errors.New("expired credentials")
	}
	return creds, nil
}

type sessionTokenAPI interface {
	GetSessionToken(context.Context, *sts.GetSessionTokenInput, ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error)
}

type sessionTokenProvider struct{ client sessionTokenAPI }

func (p *sessionTokenProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	out, err := p.client.GetSessionToken(ctx, &sts.GetSessionTokenInput{})
	if err != nil {
		return aws.Credentials{}, err
	}
	if out == nil || out.Credentials == nil {
		return aws.Credentials{}, errors.New("STS returned no session credentials")
	}
	c := out.Credentials
	if c.AccessKeyId == nil || c.SecretAccessKey == nil || c.SessionToken == nil || c.Expiration == nil {
		return aws.Credentials{}, errors.New("STS returned incomplete session credentials")
	}
	if *c.AccessKeyId == "" || *c.SecretAccessKey == "" || *c.SessionToken == "" || !c.Expiration.After(time.Now()) {
		return aws.Credentials{}, errors.New("STS returned invalid session credentials")
	}
	return aws.Credentials{
		AccessKeyID: *c.AccessKeyId, SecretAccessKey: *c.SecretAccessKey, SessionToken: *c.SessionToken,
		CanExpire: true, Expires: *c.Expiration, Source: "STSGetSessionToken",
	}, nil
}
