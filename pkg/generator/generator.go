package generator

import (
	"fmt"

	"github.com/ForgeRock/secret-agent/pkg/keytool"
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
		case 2:
			// compiled keystore
			// TODO ensure all aliases are children in dependency tree, might have missed this, it's an easy fix

			// get value for each alias
			// run keytool, passing args
		case 3:
			// individual aliases
			switch node.AliasConfig.Type {
			case types.TypeCA:
				// opendj/bin/dskeymgr create-deployment-key -f /opt/gen/secrets/generic/ds-deployment-key/deploymentkey.key -w secretValue
			case types.TypeKeyPair:
				// dskey_wrapper create-tls-key-pair -a ssl-key-pair -h openam -s CN=am
				// opendj/bin/dskeymgr create-tls-key-pair -k secretvalue -w secretvalue -K secrets/generic/am-https/keystore.p12 -W secretvalue -a ssl-key-pair -h openam -s CN=am
				// export as x509 format using dskeymgr or keytool
				contents, err := keytool.GenerateKeyPair(node)
				if err != nil {
					return err
				}
				node.Value = contents
			case types.TypeHmacKey:
				// TODO
			case types.TypeAESKey:
				// TODO
			default:
				return errors.WithStack(fmt.Errorf("Unexpected aliasConfig.Type: '%v', in %v", node.AliasConfig.Type, node.Path))
			}
		}
	default:
		return errors.WithStack(fmt.Errorf("Unexpected node.KeyConfig.Type: '%v', in %v", node.KeyConfig.Type, node.Path))
	}

	return nil
}
