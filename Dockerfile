# Build the manager binary
FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

ARG CI_JOB_TOKEN
ENV CI_JOB_TOKEN=$CI_JOB_TOKEN
ARG GOARCH=''

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

COPY hack hack

RUN ./hack/git-config.sh
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY client/ client/
COPY control/ control/
COPY controllers/ controllers/
COPY internal/ internal/
COPY encoding/ encoding/
COPY metalbond/ metalbond/
COPY netfns/ netfns/
COPY sysfs/ sysfs/
COPY ipv6manager/ ipv6manager/
COPY health/ health/
# Needed for version extraction by go build
COPY .git/ .git/

ARG TARGETOS
ARG TARGETARCH

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GO111MODULE=on go build -ldflags="-s -w -X main.buildVersion=$(git describe --tags)" -a -o manager main.go

FROM debian:bullseye-slim AS manager
WORKDIR /

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN update-ca-certificates

COPY --from=builder /workspace/manager .

ENTRYPOINT ["/manager"]
