# imds-credential-server

A maintained fork of [benkehoe/imds-credential-server](https://github.com/benkehoe/imds-credential-server). Serves refreshable AWS credentials through IMDSv2, including Kubernetes workload identity. Apache-2.0 licensed.

## Run

```sh
go install github.com/glitchedmob/imds-credential-server@main
imds-credential-server --listen 127.0.0.1:9911
```

The default listener is `127.0.0.1:9911`. Positional ports and `--port` remain supported. `--profile` selects an optional AWS profile; otherwise the AWS SDK's default credential chain applies. Static IAM user credentials are converted to cached temporary STS credentials. Root identities are rejected.

Anyone who can reach this listener can obtain its credentials. Keep it pod-local. IMDSv2 tokens are not client authentication.

## Container image

Release images will be published at `ghcr.io/glitchedmob/imds-credential-server` for `linux/amd64` and `linux/arm64`. The image contains the static binary, CA certificates, and license notices. It runs as UID/GID `65532:65532`, without a shell or writable home directory.

For a pod sidecar, keep the default loopback listener. Mount the projected token file with permissions readable by UID 65532 and set the workload-identity environment variables below. The image's `healthcheck` command supports exec probes without installing curl or a shell.

For a standalone Docker container, opt into a container-network listener and publish it only on host loopback:

```bash
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:9911:9911 \
  -e AWS_REGION -e AWS_ROLE_ARN \
  -e AWS_WEB_IDENTITY_TOKEN_FILE=/tokens/token \
  --mount type=bind,src=/path/to/projected-token-directory,dst=/tokens,readonly \
  ghcr.io/glitchedmob/imds-credential-server:<version> --listen 0.0.0.0:9911
```

The mounted directory must contain the token file and allow the non-root process to read it. In deployments, pin the image by digest. Binding to `0.0.0.0` makes credentials reachable by other containers on the same Docker network even when the published host port is loopback-only.

Build a local image with `docker build -t imds-credential-server:dev .`. The Docker build context is allowlisted so local AWS configuration and unrelated files cannot enter the image.

Run the image smoke test with `IMDS_TEST_IMAGE=imds-credential-server:dev go test -run '^TestContainer$' ./...`. It checks workload identity, IMDSv2 responses, non-root/read-only operation, health checks, and SIGTERM using synthetic credentials and a local fake STS server. `IMDS_TEST_PLATFORM=linux/arm64` selects an architecture explicitly. Docker Desktop users may need `TMPDIR` to point to a Docker-shared directory for the test token mount.

## Workload identity

Set `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, and `AWS_REGION`, and mount the projected token file. The SDK re-reads the token when refreshing credentials. EC2 metadata is disabled as an upstream source to prevent recursion; `--allow-imds` enables it explicitly.

Clients need a metadata endpoint override, or the deployment must redirect `169.254.169.254` to this listener. This server does not set up networking redirection.

`GET /healthz` checks liveness. `GET /readyz` checks credential availability. Use `imds-credential-server healthcheck` for loopback exec probes. Startup, credential retrieval, and graceful shutdown are bounded; SIGTERM shuts down cleanly.
