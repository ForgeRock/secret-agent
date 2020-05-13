package generator

import (
	"fmt"

	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/keytool"
	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/pkg/errors"
)

const (
	defaultPasswordLength = 20
)

// RecursivelyGenerateIfMissing generates secrets if not in the memory store,
//   first generating any parents
func RecursivelyGenerateIfMissing(config *secretagentv1alpha1.SecretAgentConfigurationSpec, node *secretagentv1alpha1.Node) error {
	// first generate parents, and their parents
	for _, parent := range node.Parents {
		err := RecursivelyGenerateIfMissing(config, parent)
		if err != nil {
			return err
		}
	}

	// if we're not using a SecretsManager, for keystores, ignore aliases if key exists.
	//   this avoids re-creation that would otherwise happen from not being found in SM
	if config.AppConfig.SecretsManager == secretagentv1alpha1.SecretsManagerNone {
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
func Generate(node *secretagentv1alpha1.Node) error {
	switch node.KeyConfig.Type {
	case secretagentv1alpha1.TypeLiteral:
		node.Value = []byte(node.KeyConfig.Value)
	case secretagentv1alpha1.TypePassword:
		if node.KeyConfig.Length == 0 {
			node.KeyConfig.Length = defaultPasswordLength
		}
		password, err := GeneratePassword(node.KeyConfig.Length)
		if err != nil {
			return err
		}
		node.Value = password
	case secretagentv1alpha1.TypePrivateKey:
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
			if childNode.KeyConfig.Type == secretagentv1alpha1.TypePublicKeySSH {
				if memorystore.Equal(childNode.KeyConfig.PrivateKeyPath, node.Path) {
					childNode.Value = publicKeyBytes
				}
			}
		}
	case secretagentv1alpha1.TypePublicKeySSH:
		// taken care of by privateKey
	case secretagentv1alpha1.TypeJCEKS:
		// TODO
	case secretagentv1alpha1.TypePKCS12:
		switch length := len(node.Path); length {
		case 2:
			// compiled keystore

			// get value for each alias
			// run keytool, passing args
		case 3:
			// individual aliases
			switch node.AliasConfig.Type {
			case secretagentv1alpha1.TypeCA:
				// opendj/bin/dskeymgr create-deployment-key -f /opt/gen/secrets/generic/ds-deployment-key/deploymentkey.key -w secretValue
				// TODO placeholder
				node.Value = []byte("temp-placeholder")
			case secretagentv1alpha1.TypeKeyPair:
				// dskey_wrapper create-tls-key-pair -a ssl-key-pair -h openam -s CN=am
				// opendj/bin/dskeymgr create-tls-key-pair -k secretvalue -w secretvalue -K secrets/generic/am-https/keystore.p12 -W secretvalue -a ssl-key-pair -h openam -s CN=am
				// export as x509 format using dskeymgr or keytool
				contents, err := keytool.GenerateKeyPair(node)
				if err != nil {
					return err
				}
				node.Value = contents
				// TODO placeholder
				node.Value = []byte("temp-placeholder")
			case secretagentv1alpha1.TypeHmacKey:
				// TODO placeholder
				node.Value = []byte("temp-placeholder")
			case secretagentv1alpha1.TypeAESKey:
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
