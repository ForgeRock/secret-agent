FROM gcr.io/forgerock-io/ds-empty/pit1:latest AS ds

FROM golang:1.13.10-alpine3.11 AS build
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /go/src/github.com/ForgeRock/secret-agent
COPY go.mod go.sum /go/src/github.com/ForgeRock/secret-agent/
RUN go mod download
COPY . /go/src/github.com/ForgeRock/secret-agent/
RUN go build

FROM openjdk:11-jdk-slim

RUN addgroup --gid 11111 forgerock && \
    adduser --shell /bin/bash --home /home/forgerock --uid 11111 --disabled-password --ingroup root --gecos forgerock forgerock && \
    chown -R forgerock:root /home/forgerock

WORKDIR /opt/gen

COPY --from=ds --chown=forgerock:root /opt/opendj /opt/gen/opendj
COPY --from=build --chown=forgerock:root /go/src/github.com/ForgeRock/secret-agent/secret-agent /secret-agent

RUN mkdir -p /opt/gen/secrets/generic/truststore && \
    cp $JAVA_HOME/lib/security/cacerts /opt/gen/secrets/generic/truststore && \
    chmod 764 /opt/gen/secrets/generic/truststore/cacerts && \
    chown -R forgerock:root /opt/gen

USER forgerock
