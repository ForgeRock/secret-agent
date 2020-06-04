# secret-agent

Generate secrets for the Forgerock Platform

## Features

The secret-agent generates the secrets required by the ForgeRock Platform. These secretes can be stored in-cluster as Kubernetes secrets. It can also store the secrets in a Cloud Secret Manager. Currently providers supported:

* Google Secret Manager
* AWS Secrets Manager

## Usage

### Deploy

To deploy the secret-agent, run:

```bash
kustomize build config/default | kubectl apply -f -
```

## Running the tests
* Some of the tests exercise parts of the code that os.Exec openssl and keytool
  * It's easiest to test in Docker
    * `docker build -t gcr.io/forgerock-io/secret-agent-testing:latest -f Dockerfile.testing .`
    * `docker run -it --rm -v ${PWD}:/root/go/src/github.com/Forgerock/secret-agent gcr.io/forgerock-io/secret-agent-testing:latest`
    * `go test ./...`

