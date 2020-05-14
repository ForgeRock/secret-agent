package types

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestConfigurationStructLevelValidatorLiteral(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsa",
		Type: TypeLiteral,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})
	// missing Value
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// valid
	config.Secrets[0].Keys[0].Value = "asdfKey"
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorPassword(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsa",
		Type: TypePassword,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})
	// missing Length
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// valid
	config.Secrets[0].Keys[0].Length = 16
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorPublicKeySSH(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsaKey",
		Type: TypePublicKeySSH,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})
	// missing PrivateKeyPath
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// PrivateKeyPath points to non-existent secret/key
	config.Secrets[0].Keys[0].PrivateKeyPath = []string{"myPrivateKey", "id_rsa"}
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// valid
	secret := &SecretConfig{
		Name:      "myPrivateKey",
		Namespace: "default",
		Keys: []*KeyConfig{
			&KeyConfig{
				Name: "id_rsa",
				Type: TypePrivateKey,
			},
		},
	}
	config.Secrets = append(config.Secrets, secret)
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorPKCS12(t *testing.T) {
	alias := &AliasConfig{
		Alias: "fdsaAlias",
		Type:  TypeDeploymentKey,
	}
	passwordKey := &KeyConfig{
		Name:   "fdsaPassword",
		Type:   TypePassword,
		Length: 32,
	}
	key := &KeyConfig{
		Name:                  "fdsaKey",
		Type:                  TypePKCS12,
		DeployKeyPath:         []string{"asdfSecret", "fdsaKey", "fdsaAlias"},
		DeployKeyPasswordPath: []string{"asdfSecret", "fdsaPassword"},
		KeyPassPath:           []string{"asdfSecret", "fdsaPassword"},
		StorePassPath:         []string{"asdfSecret", "fdsaPassword"},
		AliasConfigs:          []*AliasConfig{alias},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key, passwordKey)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})

	// valid
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	// missing aliasConfigs
	key.AliasConfigs = nil
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	key.AliasConfigs = append(key.AliasConfigs, alias)

	// missing keyPassPath
	key.KeyPassPath = nil
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}

	// keyPassPath must be valid
	key.KeyPassPath = []string{"asdfSecret", "non-existent"}
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	key.KeyPassPath = []string{"asdfSecret", "fdsaPassword"}

	// missing storePassPath
	key.StorePassPath = nil
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}

	// storePassPath must be valid
	key.StorePassPath = []string{"asdfSecret", "non-existent"}
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	key.StorePassPath = []string{"asdfSecret", "fdsaPassword"}
}

func TestConfigurationStructLevelValidatorTLSKeyPair(t *testing.T) {
	// setup valid to start
	alias := &AliasConfig{
		Alias:      "fdsaAlias",
		Type:       TypeTLSKeyPair,
		CommonName: "forgerock",
		Sans:       []string{".ds."},
	}
	deploymentAlias := &AliasConfig{
		Alias: "fdsaDeploymentAlias",
		Type:  TypeDeploymentKey,
	}
	passwordKey := &KeyConfig{
		Name:   "fdsaPassword",
		Type:   TypePassword,
		Length: 32,
	}
	key := &KeyConfig{
		Name:                  "fdsaKey",
		Type:                  TypePKCS12,
		DeployKeyPath:         []string{"asdfSecret", "fdsaKey", "fdsaDeploymentAlias"},
		DeployKeyPasswordPath: []string{"asdfSecret", "fdsaPassword"},
		AliasConfigs:          []*AliasConfig{alias, deploymentAlias},
		KeyPassPath:           []string{"asdfSecret", "fdsaPassword"},
		StorePassPath:         []string{"asdfSecret", "fdsaPassword"},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key, passwordKey)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})

	// valid
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	// missing commonName
	config.Secrets[0].Keys[0].AliasConfigs[0].CommonName = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	config.Secrets[0].Keys[0].AliasConfigs[0].CommonName = ".ds."

	// missing sans
	config.Secrets[0].Keys[0].AliasConfigs[0].Sans = nil
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func getConfig() *Configuration {
	return &Configuration{
		AppConfig: AppConfig{
			SecretsManager: SecretsManagerNone,
		},
		Secrets: []*SecretConfig{
			&SecretConfig{
				Name:      "asdfSecret",
				Namespace: "default",
				Keys:      []*KeyConfig{},
			},
		},
	}
}
