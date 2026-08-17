# Stage 1: Build openbao-seal-spire plugin
FROM golang:1.26-alpine AS plugin-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/openbao-seal-spire ./cmd/openbao-seal-spire

# Stage 2: SPIRE server binary extractor
FROM ghcr.io/spiffe/spire-server:1.11.0 AS spire-bin

# Target: setup container
FROM alpine:3.21 AS setup
RUN apk add --no-cache curl jq openssl ca-certificates
COPY --from=spire-bin /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY --from=plugin-builder /bin/openbao-seal-spire /openbao-seal-spire
COPY examples/setup.sh /setup.sh
RUN chmod +x /setup.sh
ENTRYPOINT ["/bin/sh", "/setup.sh"]

# Target: consumer container
FROM openbao/openbao:latest AS consumer
USER root
RUN mkdir -p /openbao/plugins
COPY --from=plugin-builder /bin/openbao-seal-spire /openbao/plugins/openbao-seal-spire
RUN chmod 755 /openbao/plugins/openbao-seal-spire
USER openbao
