package memorystore_test

import (
	"github.com/ForgeRock/secret-agent/pkg/types"
)

// GetExpectedNodesConfiguration1 exports objects for testing
func GetExpectedNodesConfiguration1() ([]*types.Node, *types.Configuration) {
	// configuration
	amBootAuthorizedKeysKeyConfig := &types.KeyConfig{
		Name:           "authorized_keys",
		Type:           types.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amBootSecretConfig := &types.SecretConfig{
		Name:      "am-boot",
		Namespace: "fr-platform",
		Keys:      []*types.KeyConfig{amBootAuthorizedKeysKeyConfig}}
	amsterIDRsaKeyConfig := &types.KeyConfig{
		Name: "id_rsa",
		Type: types.TypePrivateKey,
	}
	amsterAuthorizedKeysKeyConfig := &types.KeyConfig{
		Name:           "authorized_keys",
		Type:           types.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amsterSecretConfig := &types.SecretConfig{
		Name:      "amster",
		Namespace: "fr-platform",
		Keys: []*types.KeyConfig{
			amsterIDRsaKeyConfig,
			amsterAuthorizedKeysKeyConfig,
		},
	}
	deploymentCAAliasConfig := &types.AliasConfig{
		Alias: "deployment-ca",
		Type:  types.TypeDeploymentKey,
	}
	masterKeyPairAliasConfig := &types.AliasConfig{
		Alias: "master-key",
		Type:  types.TypeMasterKeyPair,
	}
	tlsKeyPairAliasConfig := &types.AliasConfig{
		Alias: "ssl-key-pair",
		Type:  types.TypeTLSKeyPair,
	}
	caCertAliasConfig := &types.AliasConfig{
		Alias: "ca-cert",
		Type:  types.TypeCACert,
	}
	keystoreKeyConfig := &types.KeyConfig{
		Name:                  "keystore",
		Type:                  types.TypePKCS12,
		DeployKeyPath:         []string{"ds", "keystore", "deployment-ca"},
		DeployKeyPasswordPath: []string{"ds", "deployment-ca.pin"},
		StorePassPath:         []string{"ds", "keystore.pin"},
		KeyPassPath:           []string{"ds", "keystore.pin"},
		AliasConfigs: []*types.AliasConfig{
			deploymentCAAliasConfig,
			masterKeyPairAliasConfig,
			tlsKeyPairAliasConfig,
			caCertAliasConfig,
		},
	}
	keystorePinKeyConfig := &types.KeyConfig{
		Name: "keystore.pin",
		Type: types.TypePassword,
	}
	deploymentCAPinKeyConfig := &types.KeyConfig{
		Name: "deployment-ca.pin",
		Type: types.TypePassword,
	}
	dsSecretConfig := &types.SecretConfig{
		Name:      "ds",
		Namespace: "fr-platform",
		Keys: []*types.KeyConfig{
			keystoreKeyConfig,
			keystorePinKeyConfig,
			deploymentCAPinKeyConfig,
		},
	}
	config := &types.Configuration{
		AppConfig: types.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          types.SecretsManagerNone,
		}, Secrets: []*types.SecretConfig{
			amBootSecretConfig,
			amsterSecretConfig,
			dsSecretConfig,
		},
	}

	// nodes
	nodes := []*types.Node{}
	amBootAuthorizedKeys := &types.Node{
		Path:         []string{"am-boot", "authorized_keys"},
		SecretConfig: amBootSecretConfig,
		KeyConfig:    amBootAuthorizedKeysKeyConfig,
	}
	amBootAuthorizedKeysKeyConfig.Node = amBootAuthorizedKeys
	amsterIDRsa := &types.Node{
		Path:         []string{"amster", "id_rsa"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterIDRsaKeyConfig,
	}
	amsterIDRsaKeyConfig.Node = amsterIDRsa
	amsterAuthorizedKeys := &types.Node{
		Path:         []string{"amster", "authorized_keys"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterAuthorizedKeysKeyConfig,
	}
	amsterAuthorizedKeysKeyConfig.Node = amsterAuthorizedKeys
	dsKeystore := &types.Node{
		Path:         []string{"ds", "keystore"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
	}
	keystoreKeyConfig.Node = dsKeystore
	dsKeystoreDeploymentCa := &types.Node{
		Path:         []string{"ds", "keystore", "deployment-ca"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  deploymentCAAliasConfig,
	}
	deploymentCAAliasConfig.Node = dsKeystoreDeploymentCa
	dsKeystoreMasterKeyPair := &types.Node{
		Path:         []string{"ds", "keystore", "master-key"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  masterKeyPairAliasConfig,
	}
	masterKeyPairAliasConfig.Node = dsKeystoreMasterKeyPair
	dsKeystoreTLSKeyPair := &types.Node{
		Path:         []string{"ds", "keystore", "ssl-key-pair"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  tlsKeyPairAliasConfig,
	}
	tlsKeyPairAliasConfig.Node = dsKeystoreTLSKeyPair
	dsKeystoreCACert := &types.Node{
		Path:         []string{"ds", "keystore", "ca-cert"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  caCertAliasConfig,
	}
	caCertAliasConfig.Node = dsKeystoreCACert
	dsKeystorePin := &types.Node{
		Path:         []string{"ds", "keystore.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystorePinKeyConfig,
	}
	keystorePinKeyConfig.Node = dsKeystorePin
	dsDeploymentCAPin := &types.Node{
		Path:         []string{"ds", "deployment-ca.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    deploymentCAPinKeyConfig,
	}
	deploymentCAPinKeyConfig.Node = dsDeploymentCAPin

	// amBootAuthorizedKeys
	amBootAuthorizedKeys.Parents = []*types.Node{amsterIDRsa}
	amBootAuthorizedKeys.Children = nil
	nodes = append(nodes, amBootAuthorizedKeys)
	// amsterIDRsa
	amsterIDRsa.Parents = nil
	amsterIDRsa.Children = []*types.Node{amBootAuthorizedKeys, amsterAuthorizedKeys}
	nodes = append(nodes, amsterIDRsa)
	// amsterAuthorizedKeys
	amsterAuthorizedKeys.Parents = []*types.Node{amsterIDRsa}
	amsterAuthorizedKeys.Children = nil
	nodes = append(nodes, amsterAuthorizedKeys)
	// dsKeystore
	dsKeystore.Parents = []*types.Node{
		dsKeystoreCACert,
		dsKeystoreDeploymentCa,
		dsKeystoreTLSKeyPair,
		dsKeystoreMasterKeyPair,
		dsDeploymentCAPin,
		dsKeystorePin,
	}
	dsKeystore.Children = nil
	nodes = append(nodes, dsKeystore)
	// dsKeystoreDeploymentCa
	dsKeystoreDeploymentCa.Parents = []*types.Node{dsKeystorePin, dsDeploymentCAPin}
	dsKeystoreDeploymentCa.Children = []*types.Node{
		dsKeystoreCACert,
		dsKeystoreTLSKeyPair,
		dsKeystoreMasterKeyPair,
		dsKeystore,
	}
	nodes = append(nodes, dsKeystoreDeploymentCa)
	// dsKeystoreMasterKeyPair
	dsKeystoreMasterKeyPair.Parents = []*types.Node{
		dsKeystoreDeploymentCa,
		dsDeploymentCAPin,
		dsKeystorePin,
	}
	dsKeystoreMasterKeyPair.Children = []*types.Node{dsKeystore}
	nodes = append(nodes, dsKeystoreMasterKeyPair)
	// dsKeystoreTLSKeyPair
	dsKeystoreTLSKeyPair.Parents = []*types.Node{
		dsKeystoreDeploymentCa,
		dsDeploymentCAPin,
		dsKeystorePin,
	}
	dsKeystoreTLSKeyPair.Children = []*types.Node{dsKeystore}
	nodes = append(nodes, dsKeystoreTLSKeyPair)
	// dsKeystoreCACert
	dsKeystoreCACert.Parents = []*types.Node{
		dsKeystoreDeploymentCa,
		dsDeploymentCAPin,
		dsKeystorePin,
	}
	dsKeystoreCACert.Children = []*types.Node{dsKeystore}
	nodes = append(nodes, dsKeystoreCACert)
	// dsKeystorePin
	dsKeystorePin.Parents = nil
	dsKeystorePin.Children = []*types.Node{
		dsKeystoreCACert,
		dsKeystoreDeploymentCa,
		dsKeystoreTLSKeyPair,
		dsKeystoreMasterKeyPair,
		dsKeystore,
	}
	nodes = append(nodes, dsKeystorePin)
	// dsDeploymentCAPin
	dsDeploymentCAPin.Parents = nil
	dsDeploymentCAPin.Children = []*types.Node{
		dsKeystoreCACert,
		dsKeystoreDeploymentCa,
		dsKeystoreTLSKeyPair,
		dsKeystoreMasterKeyPair,
		dsKeystore,
	}
	nodes = append(nodes, dsDeploymentCAPin)

	return nodes, config
}

// GetExpectedNodesConfiguration2 exports objects for testing
func GetExpectedNodesConfiguration2() ([]*types.Node, *types.Configuration) {
	// configuration
	secretAKeyAKeyConfig := &types.KeyConfig{
		Name:           "KeyA",
		PrivateKeyPath: []string{"SecretB", "KeyB"},
	}
	secretASecretConfig := &types.SecretConfig{
		Name:      "SecretA",
		Namespace: "default",
		Keys:      []*types.KeyConfig{secretAKeyAKeyConfig},
	}
	secretBKeyBKeyConfig := &types.KeyConfig{
		Name:           "KeyB",
		PrivateKeyPath: []string{"SecretC", "KeyC", "Alias1"},
	}
	secretBKeyCKeyConfig := &types.KeyConfig{
		Name:           "KeyC",
		PrivateKeyPath: []string{"SecretB", "KeyB"},
	}
	secretBSecretConfig := &types.SecretConfig{
		Name:      "SecretB",
		Namespace: "default",
		Keys: []*types.KeyConfig{
			secretBKeyBKeyConfig,
			secretBKeyCKeyConfig,
		},
	}
	secretCKeyCAlias1AliasConfig := &types.AliasConfig{Alias: "Alias1"}
	secretCKeyCAlias2AliasConfig := &types.AliasConfig{
		Alias: "Alias2",
	}
	secretCKeyCAlias3AliasConfig := &types.AliasConfig{
		Alias: "Alias3",
	}
	secretCKeyCAlias4AliasConfig := &types.AliasConfig{
		Alias: "Alias4",
	}
	secretCKeyCKeyConfig := &types.KeyConfig{
		Name:                  "KeyC",
		Type:                  types.TypePKCS12,
		DeployKeyPath:         []string{"SecretC", "KeyC", "Alias2"},
		DeployKeyPasswordPath: []string{"SecretD", "KeyD"},
		StorePassPath:         []string{"SecretC", "KeyD"},
		KeyPassPath:           []string{"SecretD", "KeyD"},
		AliasConfigs: []*types.AliasConfig{
			secretCKeyCAlias1AliasConfig,
			secretCKeyCAlias2AliasConfig,
			secretCKeyCAlias3AliasConfig,
			secretCKeyCAlias4AliasConfig,
		},
	}
	secretCKeyDKeyConfig := &types.KeyConfig{Name: "KeyD"}
	secretCSecretConfig := &types.SecretConfig{
		Name:      "SecretC",
		Namespace: "default",
		Keys: []*types.KeyConfig{
			secretCKeyCKeyConfig,
			secretCKeyDKeyConfig,
		},
	}
	secretDKeyDKeyConfig := &types.KeyConfig{
		Name:           "KeyD",
		PrivateKeyPath: []string{"SecretE", "KeyE"},
	}
	secretDSecretConfig := &types.SecretConfig{
		Name:      "SecretD",
		Namespace: "default",
		Keys:      []*types.KeyConfig{secretDKeyDKeyConfig},
	}
	secretEKeyEKeyConfig := &types.KeyConfig{Name: "KeyE"}
	secretESecretConfig := &types.SecretConfig{
		Name:      "SecretE",
		Namespace: "default",
		Keys:      []*types.KeyConfig{secretEKeyEKeyConfig},
	}
	config := &types.Configuration{
		AppConfig: types.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          "none",
		}, Secrets: []*types.SecretConfig{
			secretASecretConfig,
			secretBSecretConfig,
			secretCSecretConfig,
			secretDSecretConfig,
			secretESecretConfig,
		},
	}

	// nodes
	nodes := []*types.Node{}
	secretAkeyA := &types.Node{
		Path:         []string{"SecretA", "KeyA"},
		SecretConfig: secretASecretConfig,
		KeyConfig:    secretAKeyAKeyConfig,
	}
	secretAKeyAKeyConfig.Node = secretAkeyA
	secretBkeyB := &types.Node{
		Path:         []string{"SecretB", "KeyB"},
		SecretConfig: secretBSecretConfig,
		KeyConfig:    secretBKeyBKeyConfig,
	}
	secretBKeyBKeyConfig.Node = secretBkeyB
	secretBkeyC := &types.Node{
		Path:         []string{"SecretB", "KeyC"},
		SecretConfig: secretBSecretConfig,
		KeyConfig:    secretBKeyCKeyConfig,
	}
	secretBKeyCKeyConfig.Node = secretBkeyC
	secretCkeyC := &types.Node{
		Path:         []string{"SecretC", "KeyC"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
	}
	secretCKeyCKeyConfig.Node = secretCkeyC
	secretCkeyCalias1 := &types.Node{
		Path:         []string{"SecretC", "KeyC", "Alias1"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias1AliasConfig,
	}
	secretCKeyCAlias1AliasConfig.Node = secretCkeyCalias1
	secretCkeyCalias2 := &types.Node{
		Path:         []string{"SecretC", "KeyC", "Alias2"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias2AliasConfig,
	}
	secretCKeyCAlias2AliasConfig.Node = secretCkeyCalias2
	secretCkeyCalias3 := &types.Node{
		Path:         []string{"SecretC", "KeyC", "Alias3"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias3AliasConfig,
	}
	secretCKeyCAlias3AliasConfig.Node = secretCkeyCalias3
	secretCkeyCalias4 := &types.Node{
		Path:         []string{"SecretC", "KeyC", "Alias4"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias4AliasConfig,
	}
	secretCKeyCAlias4AliasConfig.Node = secretCkeyCalias4
	secretCkeyD := &types.Node{
		Path:         []string{"SecretC", "KeyD"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyDKeyConfig,
	}
	secretCKeyDKeyConfig.Node = secretCkeyD
	secretDkeyD := &types.Node{
		Path:         []string{"SecretD", "KeyD"},
		SecretConfig: secretDSecretConfig,
		KeyConfig:    secretDKeyDKeyConfig,
	}
	secretDKeyDKeyConfig.Node = secretDkeyD
	secretEkeyE := &types.Node{
		Path:         []string{"SecretE", "KeyE"},
		SecretConfig: secretESecretConfig,
		KeyConfig:    secretEKeyEKeyConfig,
	}
	secretEKeyEKeyConfig.Node = secretEkeyE

	// secretAkeyA
	secretAkeyA.Parents = []*types.Node{secretBkeyB}
	secretAkeyA.Children = nil
	nodes = append(nodes, secretAkeyA)
	// secretBkeyB
	secretBkeyB.Parents = []*types.Node{secretCkeyCalias1}
	secretBkeyB.Children = []*types.Node{secretAkeyA, secretBkeyC}
	nodes = append(nodes, secretBkeyB)
	// secretBkeyC
	secretBkeyC.Parents = []*types.Node{secretBkeyB}
	secretBkeyC.Children = nil
	nodes = append(nodes, secretBkeyC)
	// secretCkeyC
	secretCkeyC.Parents = []*types.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyD, secretDkeyD}
	secretCkeyC.Children = nil
	nodes = append(nodes, secretCkeyC)
	// secretCkeyCalias1
	secretCkeyCalias1.Parents = []*types.Node{secretCkeyCalias2, secretCkeyD, secretDkeyD}
	secretCkeyCalias1.Children = []*types.Node{secretBkeyB, secretCkeyC}
	nodes = append(nodes, secretCkeyCalias1)
	// secretCkeyCalias2
	secretCkeyCalias2.Parents = []*types.Node{secretCkeyD, secretDkeyD}
	secretCkeyCalias2.Children = []*types.Node{secretCkeyC, secretCkeyCalias1, secretCkeyCalias3, secretCkeyCalias4}
	nodes = append(nodes, secretCkeyCalias2)
	// secretCkeyCalias3
	secretCkeyCalias3.Parents = []*types.Node{secretCkeyD, secretDkeyD, secretCkeyCalias2}
	secretCkeyCalias3.Children = []*types.Node{secretCkeyC}
	nodes = append(nodes, secretCkeyCalias3)
	// secretCkeyCalias4
	secretCkeyCalias4.Parents = []*types.Node{secretCkeyD, secretDkeyD, secretCkeyCalias2}
	secretCkeyCalias4.Children = []*types.Node{secretCkeyC}
	nodes = append(nodes, secretCkeyCalias4)
	// secretCkeyD
	secretCkeyD.Parents = nil
	secretCkeyD.Children = []*types.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyC}
	nodes = append(nodes, secretCkeyD)
	// secretDkeyD
	secretDkeyD.Parents = []*types.Node{secretEkeyE}
	secretDkeyD.Children = []*types.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyC}
	nodes = append(nodes, secretDkeyD)
	// secretEkeyE
	secretEkeyE.Parents = nil
	secretEkeyE.Children = []*types.Node{secretDkeyD}
	nodes = append(nodes, secretEkeyE)

	return nodes, config
}
