package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt in after building the image. The test mounts only its own synthetic token
// and calls a local fake STS server, never a real AWS account.
func TestContainer(t *testing.T) {
	image := os.Getenv("IMDS_TEST_IMAGE")
	if image == "" {
		t.Skip("set IMDS_TEST_IMAGE to run the container smoke test")
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	mockSTS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "AssumeRoleWithWebIdentity":
			if r.Form.Get("WebIdentityToken") != "synthetic-container-token" {
				t.Error("incorrect projected token")
				w.WriteHeader(400)
				return
			}
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>synthetic-container-key</AccessKeyId><SecretAccessKey>synthetic-container-secret</SecretAccessKey><SessionToken>synthetic-container-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test</Arn><AssumedRoleId>test:test</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
		case "GetCallerIdentity":
			io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test</Arn><Account>123456789012</Account><UserId>test:test</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		default:
			t.Error("unexpected STS action")
			w.WriteHeader(400)
		}
	}))
	mockSTS.Listener.Close()
	mockSTS.Listener = listener
	mockSTS.Start()
	defer mockSTS.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tokens := t.TempDir()
	if err := os.Chmod(tokens, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokens, "token"), []byte("synthetic-container-token"), 0644); err != nil {
		t.Fatal(err)
	}

	docker := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s failed: %v\n%s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	args := []string{"run", "--detach", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--add-host=host.docker.internal:host-gateway", "--publish", "127.0.0.1::9911",
		"--mount", "type=bind,src=" + tokens + ",dst=/tokens,readonly",
		"--env", "AWS_ROLE_ARN=arn:aws:iam::123456789012:role/TestRole",
		"--env", "AWS_REGION=us-east-2", "--env", "AWS_WEB_IDENTITY_TOKEN_FILE=/tokens/token",
		"--env", "AWS_ENDPOINT_URL_STS=http://host.docker.internal:" + port,
		"--env", "NO_PROXY=*",
	}
	if platform := os.Getenv("IMDS_TEST_PLATFORM"); platform != "" {
		args = append(args, "--platform", platform)
	}
	args = append(args, image, "--listen", "0.0.0.0:9911")
	id := docker(args...)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "--force", id).Run()
	})
	address := docker("port", id, "9911/tcp")
	baseURL := "http://" + address
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(35 * time.Second)
	for {
		resp, err := client.Get(baseURL + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("container never became ready\n%s", docker("logs", id))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if docker("inspect", "--format", "{{.Config.User}}", id) != "65532:65532" {
		t.Fatal("container is not non-root")
	}
	docker("exec", id, "/imds-credential-server", "healthcheck")
	req, err := http.NewRequest(http.MethodPut, baseURL+"/latest/api/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "60")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	token, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("could not obtain IMDSv2 token")
	}
	req, err = http.NewRequest(http.MethodGet, baseURL+credentialsPath+"/TestRole", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Aws-Ec2-Metadata-Token", string(token))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var credentials Response
	err = json.NewDecoder(resp.Body).Decode(&credentials)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || credentials.AccessKeyId != "synthetic-container-key" || credentials.Token != "synthetic-container-session" {
		t.Fatal("container did not serve workload-role credentials")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("container credential response may be cached")
	}
	docker("stop", "--timeout", "15", id)
	if docker("inspect", "--format", "{{.State.ExitCode}}", id) != "0" {
		t.Fatal("container did not shut down cleanly on SIGTERM")
	}
}
