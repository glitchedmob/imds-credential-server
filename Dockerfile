FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY *.go ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/imds-credential-server .

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/glitchedmob/imds-credential-server" \
      org.opencontainers.image.title="imds-credential-server" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/imds-credential-server /imds-credential-server
COPY LICENSE NOTICE CONTRIBUTORS.md /licenses/
ENV HOME=/nonexistent AWS_EC2_METADATA_DISABLED=true
USER 65532:65532
EXPOSE 9911
HEALTHCHECK --interval=30s --timeout=6s --start-period=30s --retries=3 \
    CMD ["/imds-credential-server", "healthcheck"]
ENTRYPOINT ["/imds-credential-server"]
