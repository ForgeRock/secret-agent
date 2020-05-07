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
		Alias:        "fdsaAlias",
		Type:         TypeCA,
		Algorithm:    "ECDSAWithSHA256",
		CommonName:   "forgerock",
		PasswordPath: []string{"asdfSecret", "fdsaPassword"},
	}
	passwordKey := &KeyConfig{
		Name:   "fdsaPassword",
		Type:   TypePassword,
		Length: 32,
	}
	key := &KeyConfig{
		Name: "fdsaKey",
		Type: TypePKCS12,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, passwordKey)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})
	// missing aliasConfigs
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// valid
	key.AliasConfigs = append(key.AliasConfigs, alias)
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorCA(t *testing.T) {
	alias := &AliasConfig{
		Alias:      "fdsaAlias",
		Type:       TypeCA,
		Algorithm:  "ECDSAWithSHA256",
		CommonName: "forgerock",
	}
	key := &KeyConfig{
		Name:         "fdsaKey",
		Type:         TypePKCS12,
		AliasConfigs: []*AliasConfig{alias},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, Configuration{})
	// missing passwordPath
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// passwordPath points to non-existent secret/key
	config.Secrets[0].Keys[0].AliasConfigs[0].PasswordPath = []string{"mySecret1", "deployment-ca.pin"}
	err = validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
	// valid
	secret := &SecretConfig{
		Name:      "mySecret1",
		Namespace: "default",
		Keys: []*KeyConfig{
			&KeyConfig{
				Name:   "deployment-ca.pin",
				Type:   TypePassword,
				Length: 32,
			},
		},
	}
	config.Secrets = append(config.Secrets, secret)
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
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
