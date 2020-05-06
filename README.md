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

