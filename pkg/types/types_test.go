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
