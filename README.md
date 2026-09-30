# imds-credential-server

Serve AWS credentials through IMDSv2 for applications that only understand EC2 instance metadata. The AWS SDK handles credential lookup and refresh, including Kubernetes workload identity.

A maintained fork of [benkehoe/imds-credential-server](https://github.com/benkehoe/imds-credential-server), licensed under [Apache-2.0](LICENSE).

## Container

[GHCR images](https://github.com/glitchedmob/imds-credential-server/pkgs/container/imds-credential-server) support Linux AMD64 and ARM64. The image runs as UID/GID `65532:65532`. Token files must be readable by that user.

For projected-token credentials, export `AWS_ROLE_ARN` and `AWS_REGION`, then mount your token directory:

```sh
docker run --rm --read-only --cap-drop=ALL \
  -p 127.0.0.1:9911:9911 \
  -e AWS_REGION -e AWS_ROLE_ARN \
  -e AWS_WEB_IDENTITY_TOKEN_FILE=/tokens/token \
  --mount type=bind,src=/path/to/tokens,dst=/tokens,readonly \
  ghcr.io/glitchedmob/imds-credential-server:v1.0.1 --listen 0.0.0.0:9911
```

The default listener is `127.0.0.1:9911`. Clients can override their metadata endpoint to use it. EC2 metadata is disabled as an upstream credential source to avoid recursion.

## Kubernetes sidecar

For clients with a fixed metadata address, add `169.254.169.254` to the pod's loopback interface and serve port `80`. No host or cluster-wide routing changes are needed.

This pod spec fragment uses native sidecars, stable in Kubernetes 1.33+. Configure `aws-workload` as a ServiceAccount with AWS workload identity. Your webhook must inject `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_REGION`, and the projected token mount into `imds`.

```yaml
serviceAccountName: aws-workload
hostNetwork: false
initContainers:
  - name: imds-address
    image: alpine:3.23
    command: [ip, address, add, 169.254.169.254/32, dev, lo]
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
        add: [NET_ADMIN]
  - name: imds
    image: ghcr.io/glitchedmob/imds-credential-server:v1.0.1
    restartPolicy: Always
    args: [--listen, "169.254.169.254:80"]
    startupProbe:
      exec:
        command: [/imds-credential-server, healthcheck, --url, "http://169.254.169.254/readyz"]
      periodSeconds: 2
      failureThreshold: 30
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
        add: [NET_BIND_SERVICE]
containers:
  - name: app
    image: your-application:tag
```

The init container needs `NET_ADMIN`, which your cluster's Pod Security policy must permit. The startup probe waits for credentials before the application starts. Do not use `hostNetwork` or expose the server through a Service or Ingress.

Anyone who can reach the listener can obtain its credentials. IMDSv2 tokens are not client authentication. `/healthz` checks the HTTP server, while `/readyz` checks credential availability.
