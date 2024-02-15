#
ifndef DEFAULT_BUILDX_BUILDER
DEFAULT_BUILDX_BUILDER=default
endif

# Image URL to use all building/pushing image targets
DEFAULT_IMG_REGISTRY=us-docker.pkg.dev
DEFAULT_IMG_REPOSITORY=forgeops-public/images
ifndef DEFAULT_IMG_TAG
DEFAULT_IMG_TAG=latest
endif
IMG ?= controller:${DEFAULT_IMG_TAG}
VERSION=$(shell echo $(IMG) | awk -F ':' '{print $$2}')
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
#CRD_OPTIONS ?= "crd:trivialVersions=false"
# This will work on kube versions 1.16+. We want the CRD OpenAPI validation features in v1
CRD_OPTIONS ?= "crd:crdVersions=v1"


# if GOBIN isn't set find the path, otherwise use GOBIN
ifeq ($(GOBIN),)
GOBIN=$(shell go env GOPATH)/bin
endif

GO=$(shell go env GOROOT)/bin/go
# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec


all: manager

# Run unit and integration tests (backwards compatability)
citest: int-test
	git config --global --add safe.directory /root/go/src/github.com/ForgeRock/secret-agent
	git status --untracked-files=no --porcelain
	if [ -n "$(shell git status --untracked-files=no --porcelain)" ]; then echo "There are uncommitted changes"; false; fi
	echo "Test successful"

# Run unit tests
unit-test: setup-test generate fmt vet manifests
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; setup_envtest_env $(ENVTEST_ASSETS_DIR); $(GO) test ./... -coverprofile cover.html

# Run unit and integration tests
ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
setup-test: manifests generate fmt vet ## Run tests.
	mkdir -p ${ENVTEST_ASSETS_DIR}
	test -f ${ENVTEST_ASSETS_DIR}/setup-envtest.sh || curl -sSLo ${ENVTEST_ASSETS_DIR}/setup-envtest.sh https://raw.githubusercontent.com/kubernetes-sigs/controller-runtime/v0.8.3/hack/setup-envtest.sh
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; fetch_envtest_tools $(ENVTEST_ASSETS_DIR);

int-test: setup-test
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; setup_envtest_env $(ENVTEST_ASSETS_DIR); $(GO) test ./... -tags=intregration -coverprofile cover.out

# Run unit and integration and cloudprovider tests
cloud-test: set-test generate fmt vet manifests
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; setup_envtest_env $(ENVTEST_ASSETS_DIR); $(GO) test ./... -tags=integration,cloudprovider -coverprofile cover.html

# Build manager binary
manager: generate fmt vet
	$(GO) build -o bin/manager main.go

# debug
debug: generate fmt vet manifests
	dlv debug -- ./main.$(GO) --debug
# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	ENABLE_WEBHOOKS=false $(GO) run ./main.go

# Install CRDs into a cluster
install: manifests
	kustomize build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests
	kustomize build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	cd config/manager && kustomize edit set image controller=${IMG}
	kustomize build config/default | kubectl apply -f -

# Delete controller from the configured Kubernetes cluster in ~/.kube/config
clean: manifests
	kustomize build config/default | kubectl delete -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	# Remove "caBuncle: Cg==" from the webhook config. controller-gen generates the manifests with a placeholder
	awk '!/caBundle:/' config/webhook/manifests.yaml > t && mv t config/webhook/manifests.yaml

# Run $(GO) fmt against code
fmt:
	$(GO) fmt ./...

# Run $(GO) vet against code
vet:
	$(GO) version
	$(GO) vet ./...

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build: int-test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

docker-buildx-bake:
	REGISTRY=${DEFAULT_IMG_REGISTRY} REPOSITORY=${DEFAULT_IMG_REPOSITORY} BUILD_TAG=${DEFAULT_IMG_TAG} docker buildx bake --file=docker-bake.hcl --builder=${DEFAULT_BUILDX_BUILDER}

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	$(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.1 ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen -buildvcs=false
else
CONTROLLER_GEN=$(shell which controller-gen) -buildvcs=false
endif
