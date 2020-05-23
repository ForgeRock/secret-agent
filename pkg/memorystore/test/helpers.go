package memorystore_test

import "github.com/ForgeRock/secret-agent/api/v1alpha1"

// GetExpectedNodesConfiguration1 exports objects for testing
func GetExpectedNodesConfiguration1() ([]*v1alpha1.Node, *v1alpha1.SecretAgentConfigurationSpec) {
	// am-boot secret config
	amBootAuthorizedKeysKeyConfig := &v1alpha1.KeyConfig{
		Name:           "authorized_keys",
		Type:           v1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"amster", "id_rsa"},
	}
	amBootSecretConfig := &v1alpha1.SecretConfig{
		Name: "am-boot",
		Keys: []*v1alpha1.KeyConfig{
			amBootAuthorizedKeysKeyConfig,
		},
	}

	// am-runtime secret config
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
		Name: "amster",
		Keys: []*v1alpha1.KeyConfig{
			amsterIDRsaKeyConfig,
			amsterAuthorizedKeysKeyConfig,
		},
	}

	// platform-ca-private secret config
	platformCAPrivateCAKeyConfig := &v1alpha1.KeyConfig{
		Name: "ca",
		Type: v1alpha1.TypeCA,
	}
	platformCAPrivatePrivateKeyKeyConfig := &v1alpha1.KeyConfig{
		Name:   "private-key",
		Type:   v1alpha1.TypeCAPrivateKey,
		CAPath: []string{"platform-ca-private", "ca"},
	}
	platformCAPrivateSecretConfig := &v1alpha1.SecretConfig{
		Name: "platform-ca-private",
		Keys: []*v1alpha1.KeyConfig{
			platformCAPrivateCAKeyConfig,
			platformCAPrivatePrivateKeyKeyConfig,
		},
	}

	// platform-ca-public secret config
	platformCAPublicPublicKeyKeyConfig := &v1alpha1.KeyConfig{
		Name:           "public-key",
		Type:           v1alpha1.TypeCAPublicKey,
		PrivateKeyPath: []string{"platform-ca-private", "private-key"},
	}
	platformCAPublicSecretConfig := &v1alpha1.SecretConfig{
		Name: "platform-ca-public",
		Keys: []*v1alpha1.KeyConfig{
			platformCAPublicPublicKeyKeyConfig,
		},
	}

	// ds secret config
	dsKeystoreCACertAliasConfig := &v1alpha1.AliasConfig{
		Alias:         "ca-cert",
		Type:          v1alpha1.TypePEMPublicKeyCopy,
		PublicKeyPath: []string{"platform-ca-public", "public-key"},
	}
	dsKeystoreMasterKeyPairAliasConfig := &v1alpha1.AliasConfig{
		Alias:          "master-key-pair",
		Type:           v1alpha1.TypeKeyPair,
		SignedWithPath: []string{"platform-ca-private", "private-key"},
	}
	dsKeystoreSSLKeyPairAliasConfig := &v1alpha1.AliasConfig{
		Alias:          "ssl-key-pair",
		Type:           v1alpha1.TypeKeyPair,
		SignedWithPath: []string{"platform-ca-private", "private-key"},
	}
	dsKeystoreKeyConfig := &v1alpha1.KeyConfig{
		Name:          "keystore",
		Type:          v1alpha1.TypePKCS12,
		StorePassPath: []string{"ds", "keystore.pin"},
		KeyPassPath:   []string{"ds", "keystore.pin"},
		AliasConfigs: []*v1alpha1.AliasConfig{
			dsKeystoreCACertAliasConfig,
			dsKeystoreMasterKeyPairAliasConfig,
			dsKeystoreSSLKeyPairAliasConfig,
		},
	}
	dsKeystorePinKeyConfig := &v1alpha1.KeyConfig{
		Name: "keystore.pin",
		Type: v1alpha1.TypePassword,
	}
	dsSecretConfig := &v1alpha1.SecretConfig{
		Name: "ds",
		Keys: []*v1alpha1.KeyConfig{
			dsKeystoreKeyConfig,
			dsKeystorePinKeyConfig,
		},
	}

	// full config
	config := &v1alpha1.SecretAgentConfigurationSpec{
		AppConfig: v1alpha1.AppConfig{
			CreateKubernetesObjects: false,
			SecretsManager:          v1alpha1.SecretsManagerNone,
		}, Secrets: []*v1alpha1.SecretConfig{
			amBootSecretConfig,
			amsterSecretConfig,
			platformCAPrivateSecretConfig,
			platformCAPublicSecretConfig,
			dsSecretConfig,
		},
	}

	// nodes
	nodes := []*v1alpha1.Node{}

	// am-boot secret config
	amBootAuthorizedKeysNode := &v1alpha1.Node{
		Path:         []string{"am-boot", "authorized_keys"},
		SecretConfig: amBootSecretConfig,
		KeyConfig:    amBootAuthorizedKeysKeyConfig,
	}
	amBootAuthorizedKeysKeyConfig.Node = amBootAuthorizedKeysNode

	// am-runtime secret config
	amsterIDRsaNode := &v1alpha1.Node{
		Path:         []string{"amster", "id_rsa"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterIDRsaKeyConfig,
	}
	amsterIDRsaKeyConfig.Node = amsterIDRsaNode
	amsterAuthorizedKeysNode := &v1alpha1.Node{
		Path:         []string{"amster", "authorized_keys"},
		SecretConfig: amsterSecretConfig,
		KeyConfig:    amsterAuthorizedKeysKeyConfig,
	}
	amsterAuthorizedKeysKeyConfig.Node = amsterAuthorizedKeysNode

	// platform-ca-private secret config
	platformCAPrivateCANode := &v1alpha1.Node{
		Path:         []string{"platform-ca-private", "ca"},
		SecretConfig: platformCAPrivateSecretConfig,
		KeyConfig:    platformCAPrivateCAKeyConfig,
	}
	platformCAPrivateCAKeyConfig.Node = platformCAPrivateCANode
	platformCAPrivatePrivateKeyNode := &v1alpha1.Node{
		Path:         []string{"platform-ca-private", "private-key"},
		SecretConfig: platformCAPrivateSecretConfig,
		KeyConfig:    platformCAPrivatePrivateKeyKeyConfig,
	}
	platformCAPrivatePrivateKeyKeyConfig.Node = platformCAPrivatePrivateKeyNode

	// platform-ca-public secret config
	platformCAPublicPublicKeyNode := &v1alpha1.Node{
		Path:         []string{"platform-ca-public", "public-key"},
		SecretConfig: platformCAPublicSecretConfig,
		KeyConfig:    platformCAPublicPublicKeyKeyConfig,
	}
	platformCAPublicPublicKeyKeyConfig.Node = platformCAPublicPublicKeyNode

	// ds secret config
	dsKeystoreNode := &v1alpha1.Node{
		Path:         []string{"ds", "keystore"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    dsKeystoreKeyConfig,
	}
	dsKeystoreKeyConfig.Node = dsKeystoreNode
	dsKeystoreCACertNode := &v1alpha1.Node{
		Path:         []string{"ds", "keystore", "ca-cert"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    dsKeystoreKeyConfig,
		AliasConfig:  dsKeystoreCACertAliasConfig,
	}
	dsKeystoreCACertAliasConfig.Node = dsKeystoreCACertNode
	dsKeystoreMasterKeyPairNode := &v1alpha1.Node{
		Path:         []string{"ds", "keystore", "master-key-pair"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    dsKeystoreKeyConfig,
		AliasConfig:  dsKeystoreMasterKeyPairAliasConfig,
	}
	dsKeystoreMasterKeyPairAliasConfig.Node = dsKeystoreMasterKeyPairNode
	dsKeystoreSSLKeyPairNode := &v1alpha1.Node{
		Path:         []string{"ds", "keystore", "ssl-key-pair"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    dsKeystoreKeyConfig,
		AliasConfig:  dsKeystoreSSLKeyPairAliasConfig,
	}
	dsKeystoreSSLKeyPairAliasConfig.Node = dsKeystoreSSLKeyPairNode
	dsKeystorePinNode := &v1alpha1.Node{
		Path:         []string{"ds", "keystore.pin"},
		SecretConfig: dsSecretConfig,
		KeyConfig:    dsKeystorePinKeyConfig,
	}
	dsKeystorePinKeyConfig.Node = dsKeystorePinNode

	// parents and children
	// amBootAuthorizedKeysNode
	amBootAuthorizedKeysNode.Parents = []*v1alpha1.Node{
		amsterIDRsaNode,
	}
	amBootAuthorizedKeysNode.Children = nil
	nodes = append(nodes, amBootAuthorizedKeysNode)
	// amsterIDRsaNode
	amsterIDRsaNode.Parents = nil
	amsterIDRsaNode.Children = []*v1alpha1.Node{
		amBootAuthorizedKeysNode,
		amsterAuthorizedKeysNode,
	}
	nodes = append(nodes, amsterIDRsaNode)
	// amsterAuthorizedKeysNode
	amsterAuthorizedKeysNode.Parents = []*v1alpha1.Node{
		amsterIDRsaNode,
	}
	amsterAuthorizedKeysNode.Children = nil
	nodes = append(nodes, amsterAuthorizedKeysNode)
	// platformCAPrivateCANode
	platformCAPrivateCANode.Parents = nil
	platformCAPrivateCANode.Children = []*v1alpha1.Node{
		platformCAPrivatePrivateKeyNode,
	}
	nodes = append(nodes, platformCAPrivateCANode)
	// platformCAPrivatePrivateKeyNode
	platformCAPrivatePrivateKeyNode.Parents = []*v1alpha1.Node{
		platformCAPrivateCANode,
	}
	platformCAPrivatePrivateKeyNode.Children = []*v1alpha1.Node{
		platformCAPublicPublicKeyNode,
		dsKeystoreMasterKeyPairNode,
		dsKeystoreSSLKeyPairNode,
	}
	nodes = append(nodes, platformCAPrivatePrivateKeyNode)
	// platformCAPublicPublicKeyNode
	platformCAPublicPublicKeyNode.Parents = []*v1alpha1.Node{
		platformCAPrivatePrivateKeyNode,
	}
	platformCAPublicPublicKeyNode.Children = []*v1alpha1.Node{
		dsKeystoreCACertNode,
	}
	nodes = append(nodes, platformCAPublicPublicKeyNode)
	// dsKeystoreNode
	dsKeystoreNode.Parents = []*v1alpha1.Node{
		dsKeystoreCACertNode,
		dsKeystoreMasterKeyPairNode,
		dsKeystoreSSLKeyPairNode,
		dsKeystorePinNode,
	}
	dsKeystoreNode.Children = nil
	nodes = append(nodes, dsKeystoreNode)
	// dsKeystoreCACertNode
	dsKeystoreCACertNode.Parents = []*v1alpha1.Node{
		platformCAPublicPublicKeyNode,
		dsKeystorePinNode,
	}
	dsKeystoreCACertNode.Children = []*v1alpha1.Node{
		dsKeystoreNode,
	}
	nodes = append(nodes, dsKeystoreCACertNode)
	// dsKeystoreMasterKeyPairNode
	dsKeystoreMasterKeyPairNode.Parents = []*v1alpha1.Node{
		platformCAPrivatePrivateKeyNode,
		dsKeystorePinNode,
	}
	dsKeystoreMasterKeyPairNode.Children = []*v1alpha1.Node{
		dsKeystoreNode,
	}
	nodes = append(nodes, dsKeystoreMasterKeyPairNode)
	// dsKeystoreSSLKeyPairNode
	dsKeystoreSSLKeyPairNode.Parents = []*v1alpha1.Node{
		platformCAPrivatePrivateKeyNode,
		dsKeystorePinNode,
	}
	dsKeystoreSSLKeyPairNode.Children = []*v1alpha1.Node{
		dsKeystoreNode,
	}
	nodes = append(nodes, dsKeystoreSSLKeyPairNode)
	// dsKeystorePinNode
	dsKeystorePinNode.Parents = nil
	dsKeystorePinNode.Children = []*v1alpha1.Node{
		dsKeystoreCACertNode,
		dsKeystoreMasterKeyPairNode,
		dsKeystoreSSLKeyPairNode,
		dsKeystoreNode,
	}
	nodes = append(nodes, dsKeystorePinNode)

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
		Name: "SecretA",
		Keys: []*v1alpha1.KeyConfig{secretAKeyAKeyConfig},
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
		Name: "SecretB",
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
		Name: "SecretC",
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
		Name: "SecretD",
		Keys: []*v1alpha1.KeyConfig{secretDKeyDKeyConfig},
	}
	secretEKeyEKeyConfig := &v1alpha1.KeyConfig{Name: "KeyE"}
	secretESecretConfig := &v1alpha1.SecretConfig{
		Name: "SecretE",
		Keys: []*v1alpha1.KeyConfig{secretEKeyEKeyConfig},
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

	// parents and children
	// secretAkeyA
	secretAkeyA.Parents = []*v1alpha1.Node{
		secretBkeyB,
	}
	secretAkeyA.Children = nil
	nodes = append(nodes, secretAkeyA)
	// secretBkeyB
	secretBkeyB.Parents = []*v1alpha1.Node{
		secretCkeyCalias1,
	}
	secretBkeyB.Children = []*v1alpha1.Node{
		secretAkeyA,
		secretBkeyC,
	}
	nodes = append(nodes, secretBkeyB)
	// secretBkeyC
	secretBkeyC.Parents = []*v1alpha1.Node{
		secretBkeyB,
	}
	secretBkeyC.Children = nil
	nodes = append(nodes, secretBkeyC)
	// secretCkeyC
	secretCkeyC.Parents = []*v1alpha1.Node{
		secretCkeyCalias1,
		secretCkeyCalias2,
		secretCkeyCalias3,
		secretCkeyCalias4,
		secretCkeyD,
		secretDkeyD,
	}
	secretCkeyC.Children = nil
	nodes = append(nodes, secretCkeyC)
	// secretCkeyCalias1
	secretCkeyCalias1.Parents = []*v1alpha1.Node{
		secretCkeyD,
		secretDkeyD,
	}
	secretCkeyCalias1.Children = []*v1alpha1.Node{
		secretBkeyB,
		secretCkeyC,
		secretCkeyCalias2,
	}
	nodes = append(nodes, secretCkeyCalias1)
	// secretCkeyCalias2
	secretCkeyCalias2.Parents = []*v1alpha1.Node{
		secretCkeyD,
		secretDkeyD,
		secretCkeyCalias1,
	}
	secretCkeyCalias2.Children = []*v1alpha1.Node{
		secretCkeyC,
		secretCkeyCalias3,
	}
	nodes = append(nodes, secretCkeyCalias2)
	// secretCkeyCalias3
	secretCkeyCalias3.Parents = []*v1alpha1.Node{
		secretCkeyD,
		secretDkeyD,
		secretCkeyCalias2,
	}
	secretCkeyCalias3.Children = []*v1alpha1.Node{
		secretCkeyC,
	}
	nodes = append(nodes, secretCkeyCalias3)
	// secretCkeyCalias4
	secretCkeyCalias4.Parents = []*v1alpha1.Node{
		secretCkeyD,
		secretDkeyD,
	}
	secretCkeyCalias4.Children = []*v1alpha1.Node{
		secretCkeyC,
	}
	nodes = append(nodes, secretCkeyCalias4)
	// secretCkeyD
	secretCkeyD.Parents = nil
	secretCkeyD.Children = []*v1alpha1.Node{
		secretCkeyCalias1,
		secretCkeyCalias2,
		secretCkeyCalias3,
		secretCkeyCalias4,
		secretCkeyC,
	}
	nodes = append(nodes, secretCkeyD)
	// secretDkeyD
	secretDkeyD.Parents = []*v1alpha1.Node{
		secretEkeyE,
	}
	secretDkeyD.Children = []*v1alpha1.Node{
		secretCkeyCalias1,
		secretCkeyCalias2,
		secretCkeyCalias3,
		secretCkeyCalias4,
		secretCkeyC,
	}
	nodes = append(nodes, secretDkeyD)
	// secretEkeyE
	secretEkeyE.Parents = nil
	secretEkeyE.Children = []*v1alpha1.Node{
		secretDkeyD,
	}
	nodes = append(nodes, secretEkeyE)

	return nodes, config
}
