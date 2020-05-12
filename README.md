# secret-agent

Generate secrets for the Forgerock Platform

## Features
* Optionally store secrets in a Cloud Secret Manager, currently supported:
 * Google Secret Manager
 * AWS Secrets Manager
* Optionally apply the secrets to the Kubernetes API

## Usage
* The default `secretsConfig.yaml` generates all the secrets needed for all the products.
* Adjust the config as needed.
* Run the generator in Kubernetes using the example [manifests](manifests), `kubectl apply -f manifests`.

## Running the tests
* Some of the tests exercise parts of the code that os.Exec dskeymgr and keytool
  * It's easiest to test in Docker
    * `docker build -t gcr.io/forgerock-io/secret-agent-testing:latest -f Dockerfile.testing .`
    * `docker run -it --rm -v ${PWD}:/root/go/src/github.com/Forgerock/secret-agent gcr.io/forgerock-io/secret-agent-testing:latest`
    * `go test ./...`

