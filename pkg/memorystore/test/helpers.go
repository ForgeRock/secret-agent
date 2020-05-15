package memorystore_test

import "github.com/ForgeRock/secret-agent/api/v1alpha1"

// GetExpectedNodesConfiguration1 exports objects for testing
func GetExpectedNodesConfiguration1() ([]*v1alpha1.Node, *v1alpha1.SecretAgentConfigurationSpec) {
	// configuration
	amBootAuthorizedKeysKeyConfig := &v1alpha1.KeyConfig{
		Name:           "authorized_keys",
		Type:           v1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amBootSecretConfig := &v1alpha1.SecretConfig{
		Name:      "am-boot",
		Namespace: "fr-platform",
		Keys:      []*v1alpha1.KeyConfig{amBootAuthorizedKeysKeyConfig}}
	amsterIDRsaKeyConfig := &v1alpha1.KeyConfig{
		Name: "id_rsa",
		Type: v1alpha1.TypePrivateKey,
	}
	amsterAuthorizedKeysKeyConfig := &v1alpha1.KeyConfig{
		Name:           "authorized_keys",
		Type:           v1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amsterSecretConfig := &v1alpha1.SecretConfig{
		Name:      "amster",
		Namespace: "fr-platform",
		Keys: []*v1alpha1.KeyConfig{
			amsterIDRsaKeyConfig,
			amsterAuthorizedKeysKeyConfig,
		},
	}
	deploymentCAAliasConfig := &v1alpha1.AliasConfig{
		Alias:        "deployment-ca",
		Type:         v1alpha1.TypeCA,
		PasswordPath: []string{"ds", "deployment-ca.pin"},
	}
	masterKeyAliasConfig := &v1alpha1.AliasConfig{
		Alias: "master-key",
		Type:  v1alpha1.TypeKeyPair,
		// unrealistic, but helps with testing
		SignedWithPath: []string{"ds", "keystore", "ssl-key-pair"},
	}
	sslKeyPairAliasConfig := &v1alpha1.AliasConfig{
		Alias:          "ssl-key-pair",
		Type:           v1alpha1.TypeKeyPair,
		SignedWithPath: []string{"ds", "keystore", "deployment-ca"},
	}
	keystoreKeyConfig := &v1alpha1.KeyConfig{
		Name:          "keystore",
		Type:          v1alpha1.TypePKCS12,
		StorePassPath: []string{"ds", "keystore.pin"},
		KeyPassPath:   []string{"ds", "keystore.pin"},
		AliasConfigs: []*v1alpha1.AliasConfig{
			deploymentCAAliasConfig,
			masterKeyAliasConfig,
			sslKeyPairAliasConfig,
		},
	}
	keystorePinKeyConfig := &v1alpha1.KeyConfig{
		Name: "keystore.pin",
		Type: v1alpha1.TypePassword,
	}
	deploymentCAPinKeyConfig := &v1alpha1.KeyConfig{
		Name: "deployment-ca.pin",
		Type: v1alpha1.TypePassword,
	}
	dsSecretConfig := &v1alpha1.SecretConfig{
		Name:      "ds",
		Namespace: "fr-platform",
		Keys: []*v1alpha1.KeyConfig{
			keystoreKeyConfig,
			keystorePinKeyConfig,
			deploymentCAPinKeyConfig,
		},
	}
	config := &v1alpha1.SecretAgentConfigurationSpec{
		AppConfig: v1alpha1.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          v1alpha1.SecretsManagerNone,
		}, Secrets: []*v1alpha1.SecretConfig{
			amBootSecretConfig,
			amsterSecretConfig,
			dsSecretConfig,
		},
	}

	// nodes
	nodes := []*v1alpha1.Node{}
	amBootAuthorizedKeys := &v1alpha1.Node{
		Path:         []string{"am-boot", "authorized_keys"},
		SecretConfig: amBootSecretConfig,
		KeyConfig:    amBootAuthorizedKeysKeyConfig,
	}
	amBootAuthorizedKeysKeyConfig.Node = amBootAuthorizedKeys
	amsterIDRsa := &v1alpha1.Node{
		Path:         []string{"amster", "id_rsa"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterIDRsaKeyConfig,
	}
	amsterIDRsaKeyConfig.Node = amsterIDRsa
	amsterAuthorizedKeys := &v1alpha1.Node{
		Path:         []string{"amster", "authorized_keys"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterAuthorizedKeysKeyConfig,
	}
	amsterAuthorizedKeysKeyConfig.Node = amsterAuthorizedKeys
	dsKeystore := &v1alpha1.Node{
		Path:         []string{"ds", "keystore"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
	}
	keystoreKeyConfig.Node = dsKeystore
	dsKeystoreDeploymentCa := &v1alpha1.Node{
		Path:         []string{"ds", "keystore", "deployment-ca"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  deploymentCAAliasConfig,
	}
	deploymentCAAliasConfig.Node = dsKeystoreDeploymentCa
	dsKeystoreMasterKey := &v1alpha1.Node{
		Path:         []string{"ds", "keystore", "master-key"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  masterKeyAliasConfig,
	}
	masterKeyAliasConfig.Node = dsKeystoreMasterKey
	dsKeystoreSslKeyPair := &v1alpha1.Node{
		Path:         []string{"ds", "keystore", "ssl-key-pair"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystoreKeyConfig,
		AliasConfig:  sslKeyPairAliasConfig,
	}
	sslKeyPairAliasConfig.Node = dsKeystoreSslKeyPair
	dsKeystorePin := &v1alpha1.Node{
		Path:         []string{"ds", "keystore.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    keystorePinKeyConfig,
	}
	keystorePinKeyConfig.Node = dsKeystorePin
	dsDeploymentCAPin := &v1alpha1.Node{
		Path:         []string{"ds", "deployment-ca.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    deploymentCAPinKeyConfig,
	}
	deploymentCAPinKeyConfig.Node = dsDeploymentCAPin

	// amBootAuthorizedKeys
	amBootAuthorizedKeys.Parents = []*v1alpha1.Node{amsterIDRsa}
	amBootAuthorizedKeys.Children = nil
	nodes = append(nodes, amBootAuthorizedKeys)
	// amsterIDRsa
	amsterIDRsa.Parents = nil
	amsterIDRsa.Children = []*v1alpha1.Node{amBootAuthorizedKeys, amsterAuthorizedKeys}
	nodes = append(nodes, amsterIDRsa)
	// amsterAuthorizedKeys
	amsterAuthorizedKeys.Parents = []*v1alpha1.Node{amsterIDRsa}
	amsterAuthorizedKeys.Children = nil
	nodes = append(nodes, amsterAuthorizedKeys)
	// dsKeystore
	dsKeystore.Parents = []*v1alpha1.Node{dsKeystoreDeploymentCa, dsKeystoreMasterKey, dsKeystoreSslKeyPair, dsKeystorePin}
	dsKeystore.Children = nil
	nodes = append(nodes, dsKeystore)
	// dsKeystoreDeploymentCa
	dsKeystoreDeploymentCa.Parents = []*v1alpha1.Node{dsKeystorePin, dsDeploymentCAPin}
	dsKeystoreDeploymentCa.Children = []*v1alpha1.Node{dsKeystore, dsKeystoreSslKeyPair}
	nodes = append(nodes, dsKeystoreDeploymentCa)
	// dsKeystoreMasterKey
	dsKeystoreMasterKey.Parents = []*v1alpha1.Node{dsKeystorePin, dsKeystoreSslKeyPair}
	dsKeystoreMasterKey.Children = []*v1alpha1.Node{dsKeystore}
	nodes = append(nodes, dsKeystoreMasterKey)
	// dsKeystoreSslKeyPair
	dsKeystoreSslKeyPair.Parents = []*v1alpha1.Node{dsKeystorePin, dsKeystoreDeploymentCa}
	dsKeystoreSslKeyPair.Children = []*v1alpha1.Node{dsKeystore, dsKeystoreMasterKey}
	nodes = append(nodes, dsKeystoreSslKeyPair)
	// dsKeystorePin
	dsKeystorePin.Parents = nil
	dsKeystorePin.Children = []*v1alpha1.Node{dsKeystoreDeploymentCa, dsKeystoreMasterKey, dsKeystoreSslKeyPair, dsKeystore}
	nodes = append(nodes, dsKeystorePin)
	// dsDeploymentCAPin
	dsDeploymentCAPin.Parents = nil
	dsDeploymentCAPin.Children = []*v1alpha1.Node{dsKeystoreDeploymentCa}
	nodes = append(nodes, dsDeploymentCAPin)

	return nodes, config
}

// GetExpectedNodesConfiguration2 exports objects for testing
func GetExpectedNodesConfiguration2() ([]*v1alpha1.Node, *v1alpha1.SecretAgentConfigurationSpec) {
	// configuration
	secretAKeyAKeyConfig := &v1alpha1.KeyConfig{
		Name:           "KeyA",
		PrivateKeyPath: []string{"SecretB", "KeyB"},
	}
	secretASecretConfig := &v1alpha1.SecretConfig{
		Name:      "SecretA",
		Namespace: "default",
		Keys:      []*v1alpha1.KeyConfig{secretAKeyAKeyConfig},
	}
	secretBKeyBKeyConfig := &v1alpha1.KeyConfig{
		Name:           "KeyB",
		PrivateKeyPath: []string{"SecretC", "KeyC", "Alias1"},
	}
	secretBKeyCKeyConfig := &v1alpha1.KeyConfig{
		Name:           "KeyC",
		PrivateKeyPath: []string{"SecretB", "KeyB"},
	}
	secretBSecretConfig := &v1alpha1.SecretConfig{
		Name:      "SecretB",
		Namespace: "default",
		Keys: []*v1alpha1.KeyConfig{
			secretBKeyBKeyConfig,
			secretBKeyCKeyConfig,
		},
	}
	secretCKeyCAlias1AliasConfig := &v1alpha1.AliasConfig{Alias: "Alias1"}
	secretCKeyCAlias2AliasConfig := &v1alpha1.AliasConfig{
		Alias:          "Alias2",
		SignedWithPath: []string{"SecretC", "KeyC", "Alias1"},
	}
	secretCKeyCAlias3AliasConfig := &v1alpha1.AliasConfig{
		Alias:          "Alias3",
		SignedWithPath: []string{"SecretC", "KeyC", "Alias2"},
	}
	secretCKeyCAlias4AliasConfig := &v1alpha1.AliasConfig{
		Alias:          "Alias4",
		SignedWithPath: []string{"SecretC", "KeyD"},
	}
	secretCKeyCKeyConfig := &v1alpha1.KeyConfig{
		Name:          "KeyC",
		Type:          v1alpha1.TypePKCS12,
		StorePassPath: []string{"SecretC", "KeyD"},
		KeyPassPath:   []string{"SecretD", "KeyD"},
		AliasConfigs: []*v1alpha1.AliasConfig{
			secretCKeyCAlias1AliasConfig,
			secretCKeyCAlias2AliasConfig,
			secretCKeyCAlias3AliasConfig,
			secretCKeyCAlias4AliasConfig,
		},
	}
	secretCKeyDKeyConfig := &v1alpha1.KeyConfig{Name: "KeyD"}
	secretCSecretConfig := &v1alpha1.SecretConfig{
		Name:      "SecretC",
		Namespace: "default",
		Keys: []*v1alpha1.KeyConfig{
			secretCKeyCKeyConfig,
			secretCKeyDKeyConfig,
		},
	}
	secretDKeyDKeyConfig := &v1alpha1.KeyConfig{
		Name:           "KeyD",
		PrivateKeyPath: []string{"SecretE", "KeyE"},
	}
	secretDSecretConfig := &v1alpha1.SecretConfig{
		Name:      "SecretD",
		Namespace: "default",
		Keys:      []*v1alpha1.KeyConfig{secretDKeyDKeyConfig},
	}
	secretEKeyEKeyConfig := &v1alpha1.KeyConfig{Name: "KeyE"}
	secretESecretConfig := &v1alpha1.SecretConfig{
		Name:      "SecretE",
		Namespace: "default",
		Keys:      []*v1alpha1.KeyConfig{secretEKeyEKeyConfig},
	}
	config := &v1alpha1.SecretAgentConfigurationSpec{
		AppConfig: v1alpha1.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          "none",
		}, Secrets: []*v1alpha1.SecretConfig{
			secretASecretConfig,
			secretBSecretConfig,
			secretCSecretConfig,
			secretDSecretConfig,
			secretESecretConfig,
		},
	}

	// nodes
	nodes := []*v1alpha1.Node{}
	secretAkeyA := &v1alpha1.Node{
		Path:         []string{"SecretA", "KeyA"},
		SecretConfig: secretASecretConfig,
		KeyConfig:    secretAKeyAKeyConfig,
	}
	secretAKeyAKeyConfig.Node = secretAkeyA
	secretBkeyB := &v1alpha1.Node{
		Path:         []string{"SecretB", "KeyB"},
		SecretConfig: secretBSecretConfig,
		KeyConfig:    secretBKeyBKeyConfig,
	}
	secretBKeyBKeyConfig.Node = secretBkeyB
	secretBkeyC := &v1alpha1.Node{
		Path:         []string{"SecretB", "KeyC"},
		SecretConfig: secretBSecretConfig,
		KeyConfig:    secretBKeyCKeyConfig,
	}
	secretBKeyCKeyConfig.Node = secretBkeyC
	secretCkeyC := &v1alpha1.Node{
		Path:         []string{"SecretC", "KeyC"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
	}
	secretCKeyCKeyConfig.Node = secretCkeyC
	secretCkeyCalias1 := &v1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias1"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias1AliasConfig,
	}
	secretCKeyCAlias1AliasConfig.Node = secretCkeyCalias1
	secretCkeyCalias2 := &v1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias2"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias2AliasConfig,
	}
	secretCKeyCAlias2AliasConfig.Node = secretCkeyCalias2
	secretCkeyCalias3 := &v1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias3"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias3AliasConfig,
	}
	secretCKeyCAlias3AliasConfig.Node = secretCkeyCalias3
	secretCkeyCalias4 := &v1alpha1.Node{
		Path:         []string{"SecretC", "KeyC", "Alias4"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyCKeyConfig,
		AliasConfig:  secretCKeyCAlias4AliasConfig,
	}
	secretCKeyCAlias4AliasConfig.Node = secretCkeyCalias4
	secretCkeyD := &v1alpha1.Node{
		Path:         []string{"SecretC", "KeyD"},
		SecretConfig: secretCSecretConfig,
		KeyConfig:    secretCKeyDKeyConfig,
	}
	secretCKeyDKeyConfig.Node = secretCkeyD
	secretDkeyD := &v1alpha1.Node{
		Path:         []string{"SecretD", "KeyD"},
		SecretConfig: secretDSecretConfig,
		KeyConfig:    secretDKeyDKeyConfig,
	}
	secretDKeyDKeyConfig.Node = secretDkeyD
	secretEkeyE := &v1alpha1.Node{
		Path:         []string{"SecretE", "KeyE"},
		SecretConfig: secretESecretConfig,
		KeyConfig:    secretEKeyEKeyConfig,
	}
	secretEKeyEKeyConfig.Node = secretEkeyE

	// secretAkeyA
	secretAkeyA.Parents = []*v1alpha1.Node{secretBkeyB}
	secretAkeyA.Children = nil
	nodes = append(nodes, secretAkeyA)
	// secretBkeyB
	secretBkeyB.Parents = []*v1alpha1.Node{secretCkeyCalias1}
	secretBkeyB.Children = []*v1alpha1.Node{secretAkeyA, secretBkeyC}
	nodes = append(nodes, secretBkeyB)
	// secretBkeyC
	secretBkeyC.Parents = []*v1alpha1.Node{secretBkeyB}
	secretBkeyC.Children = nil
	nodes = append(nodes, secretBkeyC)
	// secretCkeyC
	secretCkeyC.Parents = []*v1alpha1.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyD, secretDkeyD}
	secretCkeyC.Children = nil
	nodes = append(nodes, secretCkeyC)
	// secretCkeyCalias1
	secretCkeyCalias1.Parents = []*v1alpha1.Node{secretCkeyD, secretDkeyD}
	secretCkeyCalias1.Children = []*v1alpha1.Node{secretBkeyB, secretCkeyC, secretCkeyCalias2}
	nodes = append(nodes, secretCkeyCalias1)
	// secretCkeyCalias2
	secretCkeyCalias2.Parents = []*v1alpha1.Node{secretCkeyD, secretDkeyD, secretCkeyCalias1}
	secretCkeyCalias2.Children = []*v1alpha1.Node{secretCkeyC, secretCkeyCalias3}
	nodes = append(nodes, secretCkeyCalias2)
	// secretCkeyCalias3
	secretCkeyCalias3.Parents = []*v1alpha1.Node{secretCkeyD, secretDkeyD, secretCkeyCalias2}
	secretCkeyCalias3.Children = []*v1alpha1.Node{secretCkeyC}
	nodes = append(nodes, secretCkeyCalias3)
	// secretCkeyCalias4
	secretCkeyCalias4.Parents = []*v1alpha1.Node{secretCkeyD, secretDkeyD}
	secretCkeyCalias4.Children = []*v1alpha1.Node{secretCkeyC}
	nodes = append(nodes, secretCkeyCalias4)
	// secretCkeyD
	secretCkeyD.Parents = nil
	secretCkeyD.Children = []*v1alpha1.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyC}
	nodes = append(nodes, secretCkeyD)
	// secretDkeyD
	secretDkeyD.Parents = []*v1alpha1.Node{secretEkeyE}
	secretDkeyD.Children = []*v1alpha1.Node{secretCkeyCalias1, secretCkeyCalias2, secretCkeyCalias3, secretCkeyCalias4, secretCkeyC}
	nodes = append(nodes, secretDkeyD)
	// secretEkeyE
	secretEkeyE.Parents = nil
	secretEkeyE.Children = []*v1alpha1.Node{secretDkeyD}
	nodes = append(nodes, secretEkeyE)

	return nodes, config
}
