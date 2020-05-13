package memorystore_test

import (
	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
)

// GetExpectedNodesConfiguration1 exports objects for testing
func GetExpectedNodesConfiguration1() ([]*secretagentv1alpha1.Node, *secretagentv1alpha1.SecretAgentConfigurationSpec) {
	// configuration
	amBootAuthorizedKeysKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "authorized_keys",
		Type:           secretagentv1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amBootSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "am-boot",
		Namespace: "fr-platform",
		Keys:      []*secretagentv1alpha1.KeyConfig{amBootAuthorizedKeysKeyConfig}}
	amsterIDRsaKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name: "id_rsa",
		Type: secretagentv1alpha1.TypePrivateKey,
	}
	amsterAuthorizedKeysKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "authorized_keys",
		Type:           secretagentv1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amsterSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "amster",
		Namespace: "fr-platform",
		Keys: []*secretagentv1alpha1.KeyConfig{
			amsterIDRsaKeyConfig,
			amsterAuthorizedKeysKeyConfig,
		},
	}
	deploymentCAAliasConfig := &secretagentv1alpha1.AliasConfig{
		Alias:        "deployment-ca",
		Type:         secretagentv1alpha1.TypeCA,
		PasswordPath: []string{"ds", "deployment-ca.pin"},
	}
	masterKeyAliasConfig := &secretagentv1alpha1.AliasConfig{
		Alias: "master-key",
		Type:  secretagentv1alpha1.TypeKeyPair,
		// unrealistic, but helps with testing
		SignedWithPath: []string{"ds", "keystore", "ssl-key-pair"},
	}
	sslKeyPairAliasConfig := &secretagentv1alpha1.AliasConfig{
		Alias:          "ssl-key-pair",
		Type:           secretagentv1alpha1.TypeKeyPair,
		SignedWithPath: []string{"ds", "keystore", "deployment-ca"},
	}
	keystoreKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:          "keystore",
		Type:          secretagentv1alpha1.TypePKCS12,
		StorePassPath: []string{"ds", "keystore.pin"},
		KeyPassPath:   []string{"ds", "keystore.pin"},
		AliasConfigs: []*secretagentv1alpha1.AliasConfig{
			deploymentCAAliasConfig,
			masterKeyAliasConfig,
			sslKeyPairAliasConfig,
		},
	}
	keystorePinKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name: "keystore.pin",
		Type: secretagentv1alpha1.TypePassword,
	}
	deploymentCAPinKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name: "deployment-ca.pin",
		Type: secretagentv1alpha1.TypePassword,
	}
	dsSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "ds",
		Namespace: "fr-platform",
		Keys: []*secretagentv1alpha1.KeyConfig{
			keystoreKeyConfig,
			keystorePinKeyConfig,
			deploymentCAPinKeyConfig,
		},
	}
	config := &secretagentv1alpha1.SecretAgentConfigurationSpec{
		AppConfig: secretagentv1alpha1.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          secretagentv1alpha1.SecretsManagerNone,
		}, Secrets: []*secretagentv1alpha1.SecretConfig{
			amBootSecretConfig,
			amsterSecretConfig,
			dsSecretConfig,
		},
	}

	// nodes
	nodes := []*secretagentv1alpha1.Node{}
	amBootAuthorizedKeys := &secretagentv1alpha1.Node{
		Path:         []string{"am-boot", "authorized_keys"},
		SecretConfig: amBootSecretConfig,
		KeyConfig:    amBootAuthorizedKeysKeyConfig,
	}
	amBootAuthorizedKeysKeyConfig.Node = amBootAuthorizedKeys
	amsterIDRsa := &secretagentv1alpha1.Node{
		Path:         []string{"amster", "id_rsa"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterIDRsaKeyConfig,
	}
	amsterIDRsaKeyConfig.Node = amsterIDRsa
	amsterAuthorizedKeys := &secretagentv1alpha1.Node{
		Path:         []string{"amster", "authorized_keys"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterAuthorizedKeysKeyConfig,
	}
	amsterAuthorizedKeysKeyConfig.Node = amsterAuthorizedKeys
	dsKeystore := &secretagentv1alpha1.Node{
		Path:         []string{"ds", "keystore"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
	}
	keystoreKeyConfig.Node = dsKeystore
	dsKeystoreDeploymentCa := &secretagentv1alpha1.Node{
		Path:         []string{"ds", "keystore", "deployment-ca"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  deploymentCAAliasConfig,
	}
	deploymentCAAliasConfig.Node = dsKeystoreDeploymentCa
	dsKeystoreMasterKey := &secretagentv1alpha1.Node{
		Path:         []string{"ds", "keystore", "master-key"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  masterKeyAliasConfig,
	}
	masterKeyAliasConfig.Node = dsKeystoreMasterKey
	dsKeystoreSslKeyPair := &secretagentv1alpha1.Node{
		Path:         []string{"ds", "keystore", "ssl-key-pair"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  sslKeyPairAliasConfig,
	}
	sslKeyPairAliasConfig.Node = dsKeystoreSslKeyPair
	dsKeystorePin := &secretagentv1alpha1.Node{
		Path:         []string{"ds", "keystore.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystorePinKeyConfig,
	}
	keystorePinKeyConfig.Node = dsKeystorePin
	dsDeploymentCAPin := &secretagentv1alpha1.Node{
		Path:         []string{"ds", "deployment-ca.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    deploymentCAPinKeyConfig,
	}
	deploymentCAPinKeyConfig.Node = dsDeploymentCAPin

	// amBootAuthorizedKeys
	amBootAuthorizedKeys.Parents = []*secretagentv1alpha1.Node{amsterIDRsa}
	amBootAuthorizedKeys.Children = nil
	nodes = append(nodes, amBootAuthorizedKeys)
	// amsterIDRsa
	amsterIDRsa.Parents = nil
	amsterIDRsa.Children = []*secretagentv1alpha1.Node{amBootAuthorizedKeys, amsterAuthorizedKeys}
	nodes = append(nodes, amsterIDRsa)
	// amsterAuthorizedKeys
	amsterAuthorizedKeys.Parents = []*secretagentv1alpha1.Node{amsterIDRsa}
	amsterAuthorizedKeys.Children = nil
	nodes = append(nodes, amsterAuthorizedKeys)
	// dsKeystore
	dsKeystore.Parents = []*secretagentv1alpha1.Node{dsKeystoreDeploymentCa, dsKeystoreMasterKey, dsKeystoreSslKeyPair, dsKeystorePin}
	dsKeystore.Children = nil
	nodes = append(nodes, dsKeystore)
	// dsKeystoreDeploymentCa
	dsKeystoreDeploymentCa.Parents = []*secretagentv1alpha1.Node{dsKeystorePin, dsDeploymentCAPin}
	dsKeystoreDeploymentCa.Children = []*secretagentv1alpha1.Node{dsKeystore, dsKeystoreSslKeyPair}
	nodes = append(nodes, dsKeystoreDeploymentCa)
	// dsKeystoreMasterKey
	dsKeystoreMasterKey.Parents = []*secretagentv1alpha1.Node{dsKeystorePin, dsKeystoreSslKeyPair}
	dsKeystoreMasterKey.Children = []*secretagentv1alpha1.Node{dsKeystore}
	nodes = append(nodes, dsKeystoreMasterKey)
	// dsKeystoreSslKeyPair
	dsKeystoreSslKeyPair.Parents = []*secretagentv1alpha1.Node{dsKeystorePin, dsKeystoreDeploymentCa}
	dsKeystoreSslKeyPair.Children = []*secretagentv1alpha1.Node{dsKeystore, dsKeystoreMasterKey}
	nodes = append(nodes, dsKeystoreSslKeyPair)
	// dsKeystorePin
	dsKeystorePin.Parents = nil
	dsKeystorePin.Children = []*secretagentv1alpha1.Node{dsKeystoreDeploymentCa, dsKeystoreMasterKey, dsKeystoreSslKeyPair, dsKeystore}
	nodes = append(nodes, dsKeystorePin)
	// dsDeploymentCAPin
	dsDeploymentCAPin.Parents = nil
	dsDeploymentCAPin.Children = []*secretagentv1alpha1.Node{dsKeystoreDeploymentCa}
	nodes = append(nodes, dsDeploymentCAPin)

	return nodes, config
}

// GetExpectedNodesConfiguration2 exports objects for testing
func GetExpectedNodesConfiguration2() ([]*secretagentv1alpha1.Node, *secretagentv1alpha1.SecretAgentConfigurationSpec) {
	// configuration
	secretAKeyAKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "KeyA",
		PrivateKeyPath: []string{"SecretB", "KeyB"},
	}
	secretASecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "SecretA",
		Namespace: "default",
		Keys:      []*secretagentv1alpha1.KeyConfig{secretAKeyAKeyConfig},
	}
	secretBKeyBKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "KeyB",
		PrivateKeyPath: []string{"SecretC", "KeyC", "Alias1"},
	}
	secretBKeyCKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "KeyC",
		PrivateKeyPath: []string{"SecretB", "KeyB"},
	}
	secretBSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "SecretB",
		Namespace: "default",
		Keys: []*secretagentv1alpha1.KeyConfig{
			secretBKeyBKeyConfig,
			secretBKeyCKeyConfig,
		},
	}
	secretCKeyCAlias1AliasConfig := &secretagentv1alpha1.AliasConfig{Alias: "Alias1"}
	secretCKeyCAlias2AliasConfig := &secretagentv1alpha1.AliasConfig{
		Alias:          "Alias2",
		SignedWithPath: []string{"SecretC", "KeyC", "Alias1"},
	}
	secretCKeyCAlias3AliasConfig := &secretagentv1alpha1.AliasConfig{
		Alias:          "Alias3",
		SignedWithPath: []string{"SecretC", "KeyC", "Alias2"},
	}
	secretCKeyCAlias4AliasConfig := &secretagentv1alpha1.AliasConfig{
		Alias:          "Alias4",
		SignedWithPath: []string{"SecretC", "KeyD"},
	}
	secretCKeyCKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:          "KeyC",
		Type:          secretagentv1alpha1.TypePKCS12,
		StorePassPath: []string{"SecretC", "KeyD"},
		KeyPassPath:   []string{"SecretD", "KeyD"},
		AliasConfigs: []*secretagentv1alpha1.AliasConfig{
			secretCKeyCAlias1AliasConfig,
			secretCKeyCAlias2AliasConfig,
			secretCKeyCAlias3AliasConfig,
			secretCKeyCAlias4AliasConfig,
		},
	}
	secretCKeyDKeyConfig := &secretagentv1alpha1.KeyConfig{Name: "KeyD"}
	secretCSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "SecretC",
		Namespace: "default",
		Keys: []*secretagentv1alpha1.KeyConfig{
			secretCKeyCKeyConfig,
			secretCKeyDKeyConfig,
		},
	}
	secretDKeyDKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "KeyD",
		PrivateKeyPath: []string{"SecretE", "KeyE"},
	}
	secretDSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "SecretD",
		Namespace: "default",
		Keys:      []*secretagentv1alpha1.KeyConfig{secretDKeyDKeyConfig},
	}
	secretEKeyEKeyConfig := &secretagentv1alpha1.KeyConfig{Name: "KeyE"}
	secretESecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "SecretE",
		Namespace: "default",
		Keys:      []*secretagentv1alpha1.KeyConfig{secretEKeyEKeyConfig},
	}
	config := &secretagentv1alpha1.SecretAgentConfigurationSpec{
		AppConfig: secretagentv1alpha1.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          "none",
		}, Secrets: []*secretagentv1alpha1.SecretConfig{
			secretASecretConfig,
			secretBSecretConfig,
			secretCSecretConfig,
			secretDSecretConfig,
			secretESecretConfig,
		},
	}

	// nodes
	nodes := []*secretagentv1alpha1.Node{}
	secretAkeyA := &secretagentv1alpha1.Node{
		Path:         []string{"SecretA", "KeyA"},
		SecretConfig: secretASecretConfig,
		KeyConfig:    secretAKeyAKeyConfig,
	}
	secretAKeyAKeyConfig.Node = secretAkeyA
	secretBkeyB := &secretagentv1alpha1.Node{
		Path:         []string{"SecretB", "KeyB"},
		SecretConfig: secretBSecretConfig,
		KeyConfig:    secretBKeyBKeyConfig,
	}
	secretBKeyBKeyConfig.Node = secretBkeyB
	secretBkeyC := &secretagentv1alpha1.Node{
		Path:         []string{"SecretB", "KeyC"},
		SecretConfig: secretBSecretConfig,
		KeyConfig:    secretBKeyCKeyConfig,
	}
	secretBKeyCKeyConfig.Node = secretBkeyC
	secretCkeyC := &secretagentv1alpha1.Node{
		Path:         []string{"SecretC", "KeyC"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
	}
	secretCKeyCKeyConfig.Node = secretCkeyC
	secretCkeyCalias1 := &secretagentv1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias1"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias1AliasConfig,
	}
	secretCKeyCAlias1AliasConfig.Node = secretCkeyCalias1
	secretCkeyCalias2 := &secretagentv1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias2"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias2AliasConfig,
	}
	secretCKeyCAlias2AliasConfig.Node = secretCkeyCalias2
	secretCkeyCalias3 := &secretagentv1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias3"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias3AliasConfig,
	}
	secretCKeyCAlias3AliasConfig.Node = secretCkeyCalias3
	secretCkeyCalias4 := &secretagentv1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias4"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias4AliasConfig,
	}
	secretCKeyCAlias4AliasConfig.Node = secretCkeyCalias4
	secretCkeyD := &secretagentv1alpha1.Node{
		Path:         []string{"SecretC", "KeyD"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyDKeyConfig,
	}
	secretCKeyDKeyConfig.Node = secretCkeyD
	secretDkeyD := &secretagentv1alpha1.Node{
		Path:         []string{"SecretD", "KeyD"},
		SecretConfig: secretDSecretConfig,
		KeyConfig:    secretDKeyDKeyConfig,
	}
	secretDKeyDKeyConfig.Node = secretDkeyD
	secretEkeyE := &secretagentv1alpha1.Node{
		Path:         []string{"SecretE", "KeyE"},
		SecretConfig: secretESecretConfig,
		KeyConfig:    secretEKeyEKeyConfig,
	}
	secretEKeyEKeyConfig.Node = secretEkeyE

	// secretAkeyA
	secretAkeyA.Parents = []*secretagentv1alpha1.Node{secretBkeyB}
	secretAkeyA.Children = nil
	nodes = append(nodes, secretAkeyA)
	// secretBkeyB
	secretBkeyB.Parents = []*secretagentv1alpha1.Node{secretCkeyCalias1}
	secretBkeyB.Children = []*secretagentv1alpha1.Node{secretAkeyA, secretBkeyC}
	nodes = append(nodes, secretBkeyB)
	// secretBkeyC
	secretBkeyC.Parents = []*secretagentv1alpha1.Node{secretBkeyB}
	secretBkeyC.Children = nil
	nodes = append(nodes, secretBkeyC)
	// secretCkeyC
	secretCkeyC.Parents = []*secretagentv1alpha1.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyD, secretDkeyD}
	secretCkeyC.Children = nil
	nodes = append(nodes, secretCkeyC)
	// secretCkeyCalias1
	secretCkeyCalias1.Parents = []*secretagentv1alpha1.Node{secretCkeyD, secretDkeyD}
	secretCkeyCalias1.Children = []*secretagentv1alpha1.Node{secretBkeyB, secretCkeyC, secretCkeyCalias2}
	nodes = append(nodes, secretCkeyCalias1)
	// secretCkeyCalias2
	secretCkeyCalias2.Parents = []*secretagentv1alpha1.Node{secretCkeyD, secretDkeyD, secretCkeyCalias1}
	secretCkeyCalias2.Children = []*secretagentv1alpha1.Node{secretCkeyC, secretCkeyCalias3}
	nodes = append(nodes, secretCkeyCalias2)
	// secretCkeyCalias3
	secretCkeyCalias3.Parents = []*secretagentv1alpha1.Node{secretCkeyD, secretDkeyD, secretCkeyCalias2}
	secretCkeyCalias3.Children = []*secretagentv1alpha1.Node{secretCkeyC}
	nodes = append(nodes, secretCkeyCalias3)
	// secretCkeyCalias4
	secretCkeyCalias4.Parents = []*secretagentv1alpha1.Node{secretCkeyD, secretDkeyD}
	secretCkeyCalias4.Children = []*secretagentv1alpha1.Node{secretCkeyC}
	nodes = append(nodes, secretCkeyCalias4)
	// secretCkeyD
	secretCkeyD.Parents = nil
	secretCkeyD.Children = []*secretagentv1alpha1.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyC}
	nodes = append(nodes, secretCkeyD)
	// secretDkeyD
	secretDkeyD.Parents = []*secretagentv1alpha1.Node{secretEkeyE}
	secretDkeyD.Children = []*secretagentv1alpha1.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyC}
	nodes = append(nodes, secretDkeyD)
	// secretEkeyE
	secretEkeyE.Parents = nil
	secretEkeyE.Children = []*secretagentv1alpha1.Node{secretDkeyD}
	nodes = append(nodes, secretEkeyE)

	return nodes, config
}
