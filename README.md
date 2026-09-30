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

`ghcr.io/glitchedmob/imds-credential-server:<release-tag>` supports AMD64 and ARM64. The image runs as UID/GID `65532:65532` and contains only the binary, CA certificates, and license notices. Mounted token files must be readable by that UID.

Keep the loopback listener for pod sidecars. Standalone Docker port mapping requires `--listen 0.0.0.0:9911`; restrict access to that container network. Build locally with `docker build -t imds-credential-server:dev .`.

## Workload identity

Set `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, and `AWS_REGION`, and mount the projected token file. The SDK re-reads the token when refreshing credentials. EC2 metadata is disabled as an upstream source to prevent recursion; `--allow-imds` enables it explicitly.

Clients need a metadata endpoint override, or the deployment must redirect `169.254.169.254` to this listener. This server does not set up networking redirection.

`GET /healthz` checks liveness. `GET /readyz` checks credential availability. Use `imds-credential-server healthcheck` for loopback exec probes. Startup, credential retrieval, and graceful shutdown are bounded; SIGTERM shuts down cleanly.
