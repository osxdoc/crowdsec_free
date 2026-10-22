# syntax=docker/dockerfile:1.7
#
# One image with the engine, cscli, cswebui and csblocklistd.
# Build from the repository root:
#   docker build -f deploy/docker/Dockerfile -t crowdsec-free:v1.8.2 .

FROM golang:1.27-alpine AS build

WORKDIR /src

ENV CGO_ENABLED=0
ENV GOFLAGS=-mod=readonly

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=v1.8.2

# Pure-Go SQLite: the image stays static and does not need libc/gcc.
RUN set -eux; \
    go build -trimpath -tags "netgo,osusergo,sqlite_modernc" \
        -ldflags "-s -w -X github.com/crowdsecurity/go-cs-lib/version.Version=${VERSION}" \
        -o /out/crowdsec ./cmd/crowdsec; \
    go build -trimpath -tags "netgo,osusergo,sqlite_modernc" \
        -ldflags "-s -w -X github.com/crowdsecurity/go-cs-lib/version.Version=${VERSION}" \
        -o /out/cscli ./cmd/crowdsec-cli; \
    go build -trimpath -tags "netgo,osusergo" \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/cswebui ./cmd/cswebui; \
    go build -trimpath -tags "netgo,osusergo" \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/csblocklistd ./cmd/csblocklistd

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata curl

COPY --from=build /out/ /usr/local/bin/

# Default configuration: the repository's config/ plus the container-specific
# overrides from deploy/docker/config/.
COPY config/ /etc/crowdsec-defaults/
COPY deploy/docker/config/ /etc/crowdsec-defaults/
COPY deploy/docker/bootstrap.sh /usr/local/bin/bootstrap.sh

RUN chmod 0755 /usr/local/bin/bootstrap.sh

VOLUME ["/var/lib/crowdsec/data"]

EXPOSE 8080 8081 8082 6060

CMD ["crowdsec", "-c", "/etc/crowdsec/config.yaml"]
