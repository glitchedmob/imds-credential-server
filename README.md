# imds-credential-server
**Serve refreshable AWS credentials through IMDSv2**

This is a maintained fork of [benkehoe/imds-credential-server](https://github.com/benkehoe/imds-credential-server). The original Apache-2.0 license and contributor attribution are retained.

This CLI tool runs a server compliant with the [EC2 IMDSv2 interface](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) in order to vend AWS credentials, primarily to export credentials into locally-run containers.

This is better than mounting your `~/.aws` directory into a container as a) it allows for mechanisms that only work on the host, e.g., custom credential processes and b) it only vends one set of (refreshable) credentials to the container rather than providing access to all your credentials.

## Install
Three options:
* [Download the latest release](https://github.com/glitchedmob/imds-credential-server/releases)
* Use `go install`. [`go install` will install to `$GOBIN` or `$GOPATH/bin` or `$HOME/go/bin`](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies), so ensure that directory is on your `$PATH`.
```bash
$ go install github.com/glitchedmob/imds-credential-server@main
```
* Clone the repo
```bash
$ git clone https://github.com/glitchedmob/imds-credential-server
$ cd imds-credential-server && go build .
```



## Use
Run the server in one terminal. With no arguments it listens on `127.0.0.1:9911`.
It uses the AWS SDK's default credential chain. `--profile` selects an optional named profile.

A bare port binds to loopback. Use `--listen HOST:PORT` to select another address. Anyone who can reach this listener can obtain its credentials. Do not expose it through a public service or ingress.
```bash
$ imds-credential-server 8081
```

And then run a container in a separate terminal. **Note the trailing slash on the URL.**
```bash
$ docker run --rm -p 8081:8081 -e AWS_EC2_METADATA_SERVICE_ENDPOINT=http://host.docker.internal:8081/ amazon/aws-cli sts get-caller-identity
{
    "UserId": "AROAXXXXXXXXXXXXXXXXX:SessionName",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/SomeRole/SessionName"
}
```

## Details

The default port is 9911. The positional port and `--port` flag remain supported.
For host-to-container use, map the chosen port and set the environment variable `AWS_EC2_METADATA_SERVICE_ENDPOINT` to `http://host.docker.internal:MAPPED_PORT/` with the approporiate port and **remember to include the trailing slash** (the CLI and some SDKs won't work correctly without it).

AWS SDKs run inside the container should just work, as should any tool that relies on them.
For tools that don't correctly accept the full range of AWS credential sources, check out [aws-export-credentials](https://github.com/benkehoe/aws-export-credentials), ideally using it inside the container.

For static IAM user credentials, the server uses [STS.GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html) and caches the resulting temporary credentials. Root identities are rejected. Existing temporary credentials retain their SDK refresh provider.

Use `imds-credential-server version` to print the build version.

## Workload identity

Set `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, and `AWS_REGION`. Mount the projected token file so the server can read it. The SDK re-reads that file when refreshing credentials. Do not copy its contents into configuration or images.

EC2 metadata is disabled as an upstream credential source by default, preventing the server from recursively querying itself. `--allow-imds` explicitly enables it for use outside this sidecar arrangement.

This server does not intercept traffic to `169.254.169.254`. Clients must support a metadata endpoint override, or the deployment must supply a pod-local networking override. It does not add IAM permissions beyond those of its configured credential source.

## Health and shutdown

- `GET /healthz` checks process liveness without contacting AWS.
- `GET /readyz` checks credential availability and known expiration. It does not validate authorization to a particular AWS service.
- `imds-credential-server healthcheck` checks readiness on localhost without loading AWS configuration. Use `--url http://127.0.0.1:9911/healthz` for liveness or to change the address.

Loopback-only listeners require exec probes in Kubernetes. HTTP probes aimed at the pod IP cannot reach them.

Startup validation defaults to 30 seconds. Credential retrieval and AWS HTTP requests default to 10 seconds. The HTTP server limits header reads, request reads, writes, and idle connections. SIGINT and SIGTERM stop accepting connections and drain requests with a 10-second shutdown deadline.

Use `--startup-timeout`, `--credential-timeout`, and `--shutdown-timeout` to change these limits. The credential timeout must be between zero exclusive and one minute inclusive. Temporary credentials without a known expiry, such as environment-supplied session credentials, retain the upstream one-hour advertised-expiration fallback. Prefer refreshable workload identity for long-running deployments.
