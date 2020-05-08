package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"

	"github.com/ForgeRock/secret-agent/pkg/generator"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/ForgeRock/secret-agent/pkg/types"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v2"
)

var (
	validate   *validator.Validate
	configFile = flag.String("configFile", "secretsConfig.yaml", "Path to YAML config file")
)

func main() {
	flag.Parse()

	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("error reading configuration file: %+v", err)
	}
	config := &types.Configuration{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		log.Fatalf("error parsing configuration file: %+v", err)
	}

	validate := validator.New()
	validate.RegisterStructValidation(types.ConfigurationStructLevelValidator, types.Configuration{})
	err = validate.Struct(config)
	if err != nil {
		log.Fatalf("error validating configuration file: %+v", err)
	}

	clientSet, err := k8ssecrets.GetClientSet()
	if err != nil {
		log.Fatalf("error getting Kubernetes ClientSet: %+v", err)
	}

	nodes := memorystore.GetDependencyNodes(config)
	err = memorystore.EnsureAcyclic(nodes)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	// EnsureAcyclic works by removing leaf nodes from the set of nodes, so we need to regenerate the set
	//   copy(src, dst) is not good enough, because the nodes get modified along the way
	nodes = memorystore.GetDependencyNodes(config)

	if config.AppConfig.SecretsManager != types.SecretsManagerNone {
		ctx := context.Background()
		err := secretsmanager.LoadExisting(ctx, config, nodes)
		if err != nil {
			log.Fatalf("error loading existing secrets from the Secrets Manager: %+v", err)
		}
	}

	err = k8ssecrets.LoadExisting(clientSet, config.Secrets)
	if err != nil {
		log.Fatalf("error loading existing secrets from the Kubernetes API: %+v", err)
	}

	for _, node := range nodes {
		err = generator.RecursivelyGenerateIfMissing(config, node)
		if err != nil {
			log.Fatalf("error generating secrets: %+v", err)
		}
	}

	if config.AppConfig.SecretsManager != types.SecretsManagerNone {
		ctx := context.Background()
		err = secretsmanager.EnsureSecrets(ctx, config, nodes)
		if err != nil {
			log.Fatalf("error ensuring secrets in the Secrets Manager: %+v", err)
		}
	}

	if config.AppConfig.CreateKubernetesObjects {
		err = k8ssecrets.ApplySecrets(clientSet, config.Secrets)
		if err != nil {
			log.Fatalf("error applying secrets to the Kubernetes API: %+v", err)
		}
	}
}
