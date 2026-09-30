// Copyright 2020 Ben Kehoe
// Modified by the glitchedmob fork to support maintained container deployments.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var Version = "dev"

type innerError struct {
	Code    string
	Message string
}

type errorBody struct {
	Error innerError
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{
		Error: innerError{Code: code, Message: message},
	})
}

type Config struct {
	secret         []byte
	AwsConfig      aws.Config
	PrincipalArn   string
	PrincipalName  string
	RequestTimeout time.Duration
}

func (cfg *Config) EncodeToken(ttl time.Duration) []byte {
	now := time.Now().UTC()
	expiration := now.Add(ttl)
	expirationBytes := []byte(expiration.Format(time.RFC3339Nano))
	encodedExpirationStr := base64.URLEncoding.EncodeToString(expirationBytes)

	mac := hmac.New(sha256.New, cfg.secret)
	mac.Write(expirationBytes)

	macBytes := mac.Sum(nil)
	macStr := base64.URLEncoding.EncodeToString(macBytes)

	token := make([]byte, 0, len(encodedExpirationStr)+len(macStr)+1)

	token = append(token, encodedExpirationStr...)
	token = append(token, "."...)
	token = append(token, macStr...)

	return token
}

func (cfg *Config) ValidateToken(token string) error {
	if len(token) > 512 {
		return errors.New("The IMDSv2 token is invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("The IMDSv2 token is invalid")
	}
	encodedExpirationStr := parts[0]
	macStr := parts[1]

	expirationBytes, err := base64.URLEncoding.DecodeString(encodedExpirationStr)
	if err != nil {
		return errors.New("The IMDSv2 token is invalid")
	}

	var expiration time.Time
	err = expiration.UnmarshalText(expirationBytes)
	if err != nil {
		return errors.New("The IMDSv2 token is invalid")
	}

	macBytes, err := base64.URLEncoding.DecodeString(macStr)
	if err != nil {
		return errors.New("The IMDSv2 token is invalid")
	}

	mac := hmac.New(sha256.New, cfg.secret)
	mac.Write(expirationBytes)

	expectedMacBytes := mac.Sum(nil)
	if !hmac.Equal(expectedMacBytes, macBytes) {
		return errors.New("The IMDSv2 token is invalid")
	}

	now := time.Now().UTC()
	if !expiration.After(now) {
		return errors.New("The IMDSv2 token has expired")
	}

	return nil
}

func (cfg *Config) handleTokenRequest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Token must be obtained with PUT")
		return
	}

	forwardedFor := req.Header.Get("x-forwarded-for")
	if forwardedFor != "" {
		writeError(w, http.StatusForbidden, "InvalidHeader", "Token requests can't contain X-Forwarded-For")
		return
	}

	ttlStr := req.Header.Get("x-aws-ec2-metadata-token-ttl-seconds")
	if ttlStr == "" {
		writeError(w, http.StatusBadRequest, "MissingTTL", "The IMDSv2 token expiration header is missing")
		return
	}
	ttlInt, err := strconv.Atoi(ttlStr)
	if err != nil || ttlInt <= 0 || ttlInt > 21600 {
		writeError(w, http.StatusBadRequest, "InvalidTTL", "The IMDSv2 token expiration is invalid")
		return
	}
	ttl := time.Second * time.Duration(ttlInt)

	bodyBytes := cfg.EncodeToken(ttl)
	// Go SDK V2 requires the response to have this header
	// https://github.com/aws/aws-sdk-go-v2/blob/787a81828a3812407a6d90036f07449d77a0f070/feature/ec2/imds/api_op_GetToken.go#L80
	w.Header().Add("x-aws-ec2-metadata-token-ttl-seconds", ttlStr)
	w.Header().Add("Content-type", "text/plain")
	w.Write(bodyBytes)
}

func (cfg *Config) handleRequest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		return
	}

	token := req.Header.Get("x-aws-ec2-metadata-token")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "MissingToken", "The IMDSv2 token header is missing")
		return
	}
	if err := cfg.ValidateToken(token); err != nil {
		writeError(w, http.StatusUnauthorized, "InvalidToken", err.Error())
		return
	}

	if req.URL.Path == credentialsPath || req.URL.Path == credentialsPath+"/" {
		cfg.handleRoleRequest(w, req)
		return
	}
	role := strings.TrimPrefix(req.URL.Path, credentialsPath+"/")
	cfg.handleCredentialRequest(w, req, role)
}

func (cfg *Config) handleRoleRequest(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-type", "text/plain")
	io.WriteString(w, cfg.PrincipalName)
}

// This is based on the example output in the IMDS documentation:
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
type Response struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
	// Go SDK V2 requires the status to be set and the value to be equal to "Success"
	// https://github.com/aws/aws-sdk-go-v2/blob/787a81828a3812407a6d90036f07449d77a0f070/credentials/ec2rolecreds/provider.go#L220
	Code        string
	LastUpdated string
	Type        string
}

func (cfg *Config) GenerateResponse(ctx context.Context) (Response, error) {
	creds, err := cfg.retrieveCredentials(ctx)
	if err != nil {
		return Response{}, err
	}
	expires := creds.Expires
	if expires.IsZero() {
		// Environment-provided session credentials have no advertised expiry.
		expires = time.Now().UTC().Add(time.Hour)
	}
	return Response{
		AccessKeyId: creds.AccessKeyID, SecretAccessKey: creds.SecretAccessKey,
		Token: creds.SessionToken, Expiration: expires.UTC().Format(time.RFC3339Nano),
		Code: "Success", Type: "AWS-HMAC", LastUpdated: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (cfg *Config) handleCredentialRequest(w http.ResponseWriter, req *http.Request, role string) {
	if role != cfg.PrincipalName {
		writeError(w, http.StatusNotFound, "InvalidRole", "Unknown role name")
		return
	}
	response, err := cfg.GenerateResponse(req.Context())
	if err != nil {
		log.Print("credential retrieval failed")
		writeError(w, http.StatusInternalServerError, "InternalServerError", "Something went wrong")
		return
	}

	bodyBytes, err := json.Marshal(response)
	if err != nil {
		log.Print("credential response encoding failed")
		writeError(w, http.StatusInternalServerError, "InternalServerError", "Something went wrong")
		return
	}

	w.Header().Add("Content-type", "application/json")
	w.Write(bodyBytes)
}

/*
PUT /latest/api/token -> token
GET /latest/meta-data/iam/security-credentials/ -> role name
GET /latest/meta-data/iam/security-credentials/{role_name} -> creds
*/
const credentialsPath = "/latest/meta-data/iam/security-credentials"

func (cfg *Config) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if req.URL.Path == "/healthz" || req.URL.Path == "/readyz" {
		cfg.handleHealth(w, req)
		return
	}
	if req.URL.Path == "/latest/api/token" {
		cfg.handleTokenRequest(w, req)
	} else if req.URL.Path == credentialsPath || strings.HasPrefix(req.URL.Path, credentialsPath+"/") {
		cfg.handleRequest(w, req)
	} else {
		writeError(w, http.StatusNotFound, "InvalidPath", "Invalid path")
	}
}

func (cfg *Config) handleHealth(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		return
	}
	if req.URL.Path == "/readyz" {
		if _, err := cfg.retrieveCredentials(req.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "Unavailable", "Credentials are unavailable")
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok\n")
}
