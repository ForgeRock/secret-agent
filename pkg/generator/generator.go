package generator

import (
	"fmt"

	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/ForgeRock/secret-agent/pkg/types"
	"github.com/pkg/errors"
)

const (
	defaultPasswordLength = 20
)

// RecursivelyGenerateIfMissing generates secrets if not in the memory store,
//   first generating any parents
func RecursivelyGenerateIfMissing(config *types.Configuration, node *types.Node) error {
	// first generate parents, and their parents
	for _, parent := range node.Parents {
		err := RecursivelyGenerateIfMissing(config, parent)
		if err != nil {
			return err
		}
	}

	// if we're not using a SecretsManager, for keystores, ignore aliases if key exists.
	//   this avoids re-creation that would otherwise happen from not being found in SM
	if config.AppConfig.SecretsManager == types.SecretsManagerNone {
		if len(node.Path) == 3 { // is an Alias Node
			if len(node.KeyConfig.Node.Value) != 0 { // Key Node already has Value
				return nil
			}
		}
	}

	// generate this node
	if len(node.Value) == 0 {
		err := Generate(node)
		if err != nil {
			return err
		}
	}

	return nil
}

// Generate generates a secret node
func Generate(node *types.Node) error {
	switch node.KeyConfig.Type {
	case types.TypeLiteral:
		node.Value = []byte(node.KeyConfig.Value)
	case types.TypePassword:
		if node.KeyConfig.Length == 0 {
			node.KeyConfig.Length = defaultPasswordLength
		}
		password, err := GeneratePassword(node.KeyConfig.Length)
		if err != nil {
			return err
		}
		node.Value = password
	case types.TypePrivateKey:
		// privateKey
		privateKey, privateKeyBytes, err := generateRSAPrivateKey()
		if err != nil {
			return err
		}
		node.Value = privateKeyBytes

		// publicKeySSH
		publicKeyBytes, err := generateRSAPublicKeySSH(privateKey)
		if err != nil {
			return err
		}
		// find public key node(s)
		for _, childNode := range node.Children {
			if childNode.KeyConfig.Type == types.TypePublicKeySSH {
				if memorystore.Equal(childNode.KeyConfig.PrivateKeyPath, node.Path) {
					childNode.Value = publicKeyBytes
				}
			}
		}
	case types.TypePublicKeySSH:
		// taken care of by privateKey
	case types.TypeJCEKS:
		// TODO
	case types.TypePKCS12:
		switch length := len(node.Path); length {
		case 2: // compiled keystore
			value, err := GetKeystore()
			if err != nil {
				return err
			}

			node.Value = value
		case 3: // individual aliases
			switch node.AliasConfig.Type {
			case types.TypeDeploymentKey:
				deploymentKeyPassword, err := getValueFromParent(node.KeyConfig.DeployKeyPasswordPath, node)
				if err != nil {
					return err
				}

				value, err := GenerateDeploymentKey(deploymentKeyPassword)
				if err != nil {
					return err
				}

				node.Value = value
			case types.TypeTLSKeyPair:
				storePassword, deploymentKey, deploymentKeyPassword, err := getStorePassDeployKeyDeployKeyPassword(node)
				if err != nil {
					return err
				}

				contents, err := GenerateTLSKeyPair(storePassword, deploymentKey, deploymentKeyPassword, node.AliasConfig)
				if err != nil {
					return err
				}

				node.Value = contents
			case types.TypeMasterKeyPair:
				storePassword, deploymentKey, deploymentKeyPassword, err := getStorePassDeployKeyDeployKeyPassword(node)
				if err != nil {
					return err
				}

				contents, err := GenerateMasterKeyPair(storePassword, deploymentKey, deploymentKeyPassword, node.AliasConfig)
				if err != nil {
					return err
				}

				node.Value = contents
			case types.TypeCACert:
				storePassword, deploymentKey, deploymentKeyPassword, err := getStorePassDeployKeyDeployKeyPassword(node)
				if err != nil {
					return err
				}

				contents, err := GenerateCACert(storePassword, deploymentKey, deploymentKeyPassword, node.AliasConfig)
				if err != nil {
					return err
				}

				node.Value = contents
			default:
				return errors.WithStack(fmt.Errorf("Unexpected aliasConfig.Type: '%v', in %v", node.AliasConfig.Type, node.Path))
			}
		}
	default:
		return errors.WithStack(fmt.Errorf("Unexpected node.KeyConfig.Type: '%v', in %v", node.KeyConfig.Type, node.Path))
	}

	return nil
}

func getStorePassDeployKeyDeployKeyPassword(node *types.Node) ([]byte, []byte, []byte, error) {
	storePassword, deploymentKey, deploymentKeyPassword := []byte{}, []byte{}, []byte{}
	// fetch the storepass password
	storePassword, err := getValueFromParent(node.KeyConfig.StorePassPath, node)
	if err != nil {
		return storePassword, deploymentKey, deploymentKeyPassword, err
	}

	// fetch the deployment key
	deploymentKey, err = getValueFromParent(node.KeyConfig.DeployKeyPath, node)
	if err != nil {
		return storePassword, deploymentKey, deploymentKeyPassword, err
	}

	// fetch the deployment key password
	deploymentKeyPassword, err = getValueFromParent(node.KeyConfig.DeployKeyPasswordPath, node)
	if err != nil {
		return storePassword, deploymentKey, deploymentKeyPassword, err
	}

	return storePassword, deploymentKey, deploymentKeyPassword, nil
}

// noParentWithPathError allows for type checking in tests
type noParentWithPathError struct {
	nodePath   []string
	parentPath []string
}

func (cfg *noParentWithPathError) Error() string {
	return fmt.Sprintf("%v has no parent node with path: %v", cfg.nodePath, cfg.parentPath)
}

// emptyValueError allows for type checking in tests
type emptyValueError []string

func (path *emptyValueError) Error() string {
	return fmt.Sprintf("Expected value length to be non-zero for node: %v", []string(*path))
}

func getValueFromParent(path []string, node *types.Node) ([]byte, error) {
	value := []byte{}
	found := false
	for _, parentNode := range node.Parents {
		if memorystore.Equal(parentNode.Path, path) {
			value = parentNode.Value
			found = true
			break
		}
	}
	if !found {
		err := noParentWithPathError{nodePath: node.Path, parentPath: path}
		return value, errors.WithStack(&err)
	}
	if len(value) == 0 {
		err := emptyValueError(path)
		return value, errors.WithStack(&err)
	}

	return value, nil
}
