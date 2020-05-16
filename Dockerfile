# For building gcr.io/forgerock-io/secret-agent:latest
FROM gcr.io/forgerock-io/ds-empty/pit1:latest AS ds

# Build the manager binary
FROM golang:1.14-alpine as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY . .

# Build with "-s -w" linker flags to omit the symbol table, debug information and the DWARF table
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags "-s -w" -a -o manager main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details

# FROM gcr.io/distroless/static:nonroot
# WORKDIR /
# COPY --from=builder /workspace/manager .
# USER nonroot:nonroot

# ENTRYPOINT ["/manager"]


FROM openjdk:11-jdk-slim

RUN addgroup --gid 11111 forgerock && \
    adduser --shell /bin/bash --home /home/forgerock --uid 11111 --disabled-password --ingroup root --gecos forgerock forgerock && \
    chown -R forgerock:root /home/forgerock

WORKDIR /opt/gen

COPY --from=ds --chown=forgerock:root /opt/opendj /opt/gen/opendj
COPY --from=builder --chown=forgerock:root /workspace/manager /

RUN mkdir -p /opt/gen/secrets/generic/truststore && \
    cp $JAVA_HOME/lib/security/cacerts /opt/gen/secrets/generic/truststore && \
    chmod 764 /opt/gen/secrets/generic/truststore/cacerts && \
    chown -R forgerock:root /opt/gen

USER forgerock
