# For building forgerock/secret-agent:tagname

# Global build arguments
ARG GO_VERSION="1.25.9"
ARG GO_PACKAGE_SHA256="00859d7bd6defe8bf84d9db9e57b9a4467b2887c18cd93ae7460e713db774bc1"
ARG KUBEBUILDER_VERSION="3.1.0"

FROM amazoncorretto:26-alpine3.23-jdk AS tester

ARG GO_VERSION
ARG GO_PACKAGE_SHA256
ARG KUBEBUILDER_VERSION
ARG TARGETARCH

ENV CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH

RUN apk -U upgrade && \
    apk add curl make tar gzip openssl git

RUN curl -LO https://dl.google.com/go/go${GO_VERSION}.linux-$TARGETARCH.tar.gz && \
    SUM=$(sha256sum go${GO_VERSION}.linux-$TARGETARCH.tar.gz | awk '{print $1}') && \
    if [ "${SUM}" != "${GO_PACKAGE_SHA256}" ]; then echo "Failed checksum"; exit 1; fi && \
    tar xf go${GO_VERSION}.linux-$TARGETARCH.tar.gz && \
    chown -R root:root ./go && \
    mv go /usr/local && \
    rm go${GO_VERSION}.linux-$TARGETARCH.tar.gz

RUN curl -L -o kubebuilder https://go.kubebuilder.io/dl/${KUBEBUILDER_VERSION}/$(go env GOOS)/$(go env GOARCH) \
        && install kubebuilder /usr/local/bin/kubebuilder \
            && /usr/local/go/bin/go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.0

ENV PATH="/usr/local/go/bin:${PATH}:/root/go/bin" GOPATH="/root/go"
WORKDIR /root/go/src/github.com/ForgeRock/secret-agent

CMD ["sh"]


# Build the manager binary
FROM golang:${GO_VERSION}-alpine3.23 AS builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.sum ./
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download
# Copy the go source
COPY . .
# Build with "-s -w" linker flags to omit the symbol table, debug information and the DWARF table
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GO111MODULE=on go build -ldflags "-s -w" -a -o manager main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details

# FROM gcr.io/distroless/static:nonroot
# WORKDIR /
# COPY --from=builder /workspace/manager .
# USER nonroot:nonroot

# ENTRYPOINT ["/manager"]


FROM amazoncorretto:26-alpine3.23-jdk AS release

RUN addgroup --gid 11111 secret-agent && \
    adduser --shell /bin/bash --home /home/secret-agent --uid 11111 --disabled-password --ingroup root --gecos secret-agent secret-agent && \
    chown -R secret-agent:root /home/secret-agent

WORKDIR /opt/gen
COPY --from=builder --chown=secret-agent:root /workspace/manager /

RUN apk -U upgrade && \
    apk add openssl

USER 11111

CMD ["sh"]
