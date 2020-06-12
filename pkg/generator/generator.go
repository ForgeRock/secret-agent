package generator

import (
	"fmt"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/pkg/errors"
)

const (
	defaultPasswordLength = 20
)

// RecursivelyGenerateIfMissing generates secrets if not in the memory store,
//   first generating any parents
func RecursivelyGenerateIfMissing(config *v1alpha1.SecretAgentConfigurationSpec, node *v1alpha1.Node) error {
	// first generate parents, and their parents
	for _, parent := range node.Parents {
		err := RecursivelyGenerateIfMissing(config, parent)
		if err != nil {
			return err
		}
	}

	// if we're not using a SecretsManager, for keystores, ignore aliases if key exists.
	//   this avoids re-creation that would otherwise happen from not being found in SM
	if config.AppConfig.SecretsManager == v1alpha1.SecretsManagerNone {
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
func Generate(node *v1alpha1.Node) error {
	switch node.KeyConfig.Type {
	case v1alpha1.TypeLiteral:
		node.Value = []byte(node.KeyConfig.Value)
	case v1alpha1.TypePassword:
		if node.KeyConfig.Length == 0 {
			node.KeyConfig.Length = defaultPasswordLength
		}
		password, err := GeneratePassword(node.KeyConfig.Length)
		if err != nil {
			return err
		}

		node.Value = password
	case v1alpha1.TypePrivateKey:
		privateKeyPEM, err := generateRSAPrivateKey()
		if err != nil {
			return err
		}

		node.Value = privateKeyPEM
	case v1alpha1.TypePublicKeySSH:
		privateKeyPEM, err := getValueFromParent(node.KeyConfig.PrivateKeyPath, node)
		if err != nil {
			return err
		}

		publicKeyPEM, err := getRSAPublicKeySSHFromPrivateKey(privateKeyPEM)
		if err != nil {
			return err
		}

		node.Value = publicKeyPEM
	case v1alpha1.TypeCA:
		rootCA, err := GenerateRootCA("ForgeRock")
		if err != nil {
			return err
		}

		node.Value = rootCA.CertPEM

		// find private key node(s)
		for _, childNode := range node.Children {
			if childNode.KeyConfig.Type == v1alpha1.TypeCAPrivateKey {
				if memorystore.Equal(childNode.KeyConfig.CAPath, node.Path) {
					childNode.Value = rootCA.PrivateKeyPEM
				}
			}
		}
	case v1alpha1.TypeCAPrivateKey:
		// taken care of by TypeCA
	case v1alpha1.TypeCACopy:
		caPEM, err := getValueFromParent(node.KeyConfig.CAPath, node)
		if err != nil {
			return err
		}

		node.Value = caPEM
	case v1alpha1.TypeJCEKS:
		// TODO
	case v1alpha1.TypePKCS12:
		switch length := len(node.Path); length {
		case 2: // compiled keystore
			value, err := GetKeystore(node.Path)
			if err != nil {
				return errors.WithStack(err)
			}

			node.Value = value
		case 3: // individual aliases
			switch node.AliasConfig.Type {
			case v1alpha1.TypeCACopyAlias:
				caCertPEM, err := getValueFromParent(node.AliasConfig.CAPath, node)
				if err != nil {
					return err
				}
				storePassword, err := getValueFromParent(node.KeyConfig.StorePassPath, node)
				if err != nil {
					return err
				}
				err = ImportCertFromPEM(caCertPEM, storePassword, node.AliasConfig)
				if err != nil {
					return err
				}

				node.Value = caCertPEM
			case v1alpha1.TypeKeyPair:
				var certAndKeyPEM, certPEM, keyPEM []byte
				var err error
				if !node.AliasConfig.SharedCert {
					// get private key's PEM value
					rootCAPrivateKeyPEM, err := getValueFromParent(node.AliasConfig.SignedWithPath, node)
					if err != nil {
						return err
					}

					// get private key's CA PEM value
					rootCAPEM := []byte{}
					for _, parentNode := range node.Parents {
						if memorystore.Equal(node.AliasConfig.SignedWithPath, parentNode.Path) {
							rootCAPEM, err = getValueFromParent(parentNode.KeyConfig.CAPath, parentNode)
							if err != nil {
								return err
							}
							break
						}
					}
					if len(rootCAPEM) == 0 {
						return errors.New("Failed to find root CA PEM value")
					}

					// generate
					certAndKeyPEM, certPEM, keyPEM, err = GenerateSignedCertPEM(
						rootCAPEM,
						rootCAPrivateKeyPEM,
						node.AliasConfig.Algorithm,
						node.AliasConfig.CommonName,
						node.AliasConfig.Sans,
					)
					if err != nil {
						return err
					}
				} else if node.AliasConfig.SharedCert {
					certAndKeyPEM, certPEM, keyPEM, err = GenerateSharedCertPEM(node.AliasConfig.CommonName)
					if err != nil {
						return errors.WithStack(err)
					}
				} else {
					return errors.New("Cert should be either SharedCert or Signed")
				}

				// add to keystore
				storePassword, err := getValueFromParent(node.KeyConfig.StorePassPath, node)
				if err != nil {
					return err
				}
				fmt.Printf("----------%s----------\n", node.AliasConfig.CommonName)
				fmt.Printf("cert to be imported: %+v \n", string(certPEM))
				fmt.Printf("key to be imported: %+v \n", string(keyPEM))
				err = ImportKeyPairFromPEMs(certPEM, keyPEM, storePassword, node.AliasConfig)
				if err != nil {
					return err
				}

				node.Value = certAndKeyPEM
			case v1alpha1.TypeHMACKey:
				// TODO placeholder
				node.Value = []byte("temp-placeholder")
			case v1alpha1.TypeAESKey:
				// TODO placeholder
				node.Value = []byte("temp-placeholder")
			default:
				return errors.WithStack(fmt.Errorf("Unexpected aliasConfig.Type: '%v', in %v", node.AliasConfig.Type, node.Path))
			}
		}
	default:
		return errors.WithStack(fmt.Errorf("Unexpected node.KeyConfig.Type: '%v', in %v", node.KeyConfig.Type, node.Path))
	}

	return nil
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

func getValueFromParent(path []string, node *v1alpha1.Node) ([]byte, error) {
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
