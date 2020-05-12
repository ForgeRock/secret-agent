package types

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

// Config Type Strings
const (
	TypeLiteral      = "literal"
	TypePassword     = "password"
	TypePrivateKey   = "privateKey"
	TypePublicKeySSH = "publicKeySSH"
	TypeJCEKS        = "jceks"
	TypePKCS12       = "pkcs12"
	TypeCA           = "ca"
	TypeKeyPair      = "keyPair"
	TypeHmacKey      = "hmacKey"
	TypeAESKey       = "aesKey"
)

// SecretsManager Strings
const (
	SecretsManagerNone = "none"
	SecretsManagerGCP  = "GCP"
	SecretsManagerAWS  = "AWS"
)

// AppConfig is the configuration for the forgeops-secrets application
type AppConfig struct {
	CreateKubernetesObjects bool   `yaml:"createKubernetesObjects"`
	SecretsManager          string `yaml:"secretsManager" validate:"required,oneof=none GCP AWS"`
	GCPProjectID            string `yaml:"gcpProjectID"`
	AWSRegion               string `yaml:"awsRegion"`
}

// Configuration is the configuration for the forgeops-secrets application
//   and the secrets it manages
type Configuration struct {
	AppConfig AppConfig       `yaml:"appConfig" validate:"required,dive,required"`
	Secrets   []*SecretConfig `yaml:"secrets" validate:"dive,required,unique=Name,gt=0,dive,required"`
}

// SecretConfig is the configuration for a specific Kubernetes secret
type SecretConfig struct {
	Name      string       `yaml:"name" validate:"required"`
	Namespace string       `yaml:"namespace" validate:"required"`
	Keys      []*KeyConfig `yaml:"keys" validate:"dive,required,unique=Name,gt=0,dive,required"`
}

// KeyConfig is the configuration for a specific data key
type KeyConfig struct {
	Name           string         `yaml:"name" validate:"required"`
	Type           string         `yaml:"type" validate:"required,oneof=jceks literal password privateKey publicKeySSH pkcs12 jks jceks"`
	Value          string         `yaml:"value,omitempty"`
	Length         int            `yaml:"length,omitempty"`
	PrivateKeyPath []string       `yaml:"privateKeyPath,omitempty"`
	StorePassPath  []string       `yaml:"storePassPath,omitempty"`
	KeyPassPath    []string       `yaml:"keyPassPath,omitempty"`
	AliasConfigs   []*AliasConfig `yaml:"keystoreAliases,omitempty" validate:"dive"`
	Node           *Node
}

// AliasConfig is the configuration for a keystore alias
type AliasConfig struct {
	Alias          string   `yaml:"alias" validate:"required"`
	Type           string   `yaml:"type" validate:"required,oneof=ca keyPair hmacKey aesKey"`
	Algorithm      string   `yaml:"algorithm" validate:"oneof='' ECDSAWithSHA256 SHA256withRSA"`
	CommonName     string   `yaml:"commonName"`
	Sans           []string `yaml:"sans"`
	SignedWithPath []string `yaml:"signedWithPath"`
	PasswordPath   []string `yaml:"passwordPath"`
	Node           *Node
}

// Node is a dependency tree branch or leaf
// Path is of form secret Name, data Key, and keystore Alias if exists
type Node struct {
	Path         []string
	Parents      []*Node
	Children     []*Node
	SecretConfig *SecretConfig
	KeyConfig    *KeyConfig
	AliasConfig  *AliasConfig
	Value        []byte
}

// ConfigurationStructLevelValidator ensures configuration is usable
func ConfigurationStructLevelValidator(sl validator.StructLevel) {
	config := sl.Current().Interface().(Configuration)

	// AppConfig
	switch config.AppConfig.SecretsManager {
	case SecretsManagerGCP:
		if config.AppConfig.GCPProjectID == "" {
			sl.ReportError(config.AppConfig.GCPProjectID, "gcpProjectID", "GCPProjectID", "emptyGCPProjectID", "")
		}
	case SecretsManagerAWS:
		if config.AppConfig.AWSRegion == "" {
			sl.ReportError(config.AppConfig.AWSRegion, "awsRegion", "AWSRegion", "emptyAWSRegion", "")
		}
	}

	// Secrets
	for secretIndex, secret := range config.Secrets {
		for keyIndex, key := range secret.Keys {
			switch key.Type {
			case TypeLiteral:
				// must have Value
				if key.Value == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Value, "value", "Value", "literalValueEmpty", "")
				}
			case TypePassword:
				// must have Length
				if key.Length == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Length, "length", "Length", "passwordLengthZero", "")
				}
			// if type publicKeySSH, must have privateKey
			case TypePublicKeySSH:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				// must have privateKeyPath
				if len(key.PrivateKeyPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotSet", "")
					return
				}
				// privateKeyPath must be valid
				if !pathExistsInSecretConfigs(key.PrivateKeyPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotFound", "")
				}
			case TypePKCS12:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				// must have keystoreAliases
				if len(key.AliasConfigs) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs, name, "AliasConfigs", "keystoreAliasesNotSet", "")
					return
				}
				// must have keyPassPath
				if len(key.KeyPassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "KeyPassPath", "keyPassPathNotFound", "")
					return
				}
				// keyPassPath must be valid
				if !pathExistsInSecretConfigs(key.KeyPassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "KeyPassPath", "keyPassPathNotValid", "")
					return
				}
				// must have storePassPath
				if len(key.StorePassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].StorePassPath, name, "StorePassPath", "storePassPathNotFound", "")
					return
				}
				// storePassPath must be valid
				if !pathExistsInSecretConfigs(key.StorePassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "StorePassPath", "storePassPathNotValid", "")
					return
				}
				for aliasIndex, alias := range key.AliasConfigs {
					switch alias.Type {
					case TypeCA:
						name := fmt.Sprintf("Secrets.%s.%s.%s",
							config.Secrets[secretIndex].Name,
							config.Secrets[secretIndex].Keys[keyIndex].Name,
							config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias,
						)
						// must have passwordPath
						if len(alias.PasswordPath) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "CA", "passwordPathNotSet", "")
							return
						}
						// passwordPath must be valid
						if !pathExistsInSecretConfigs(alias.PasswordPath, config.Secrets) {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "CA", "passwordPathNotFound", "")
							return
						}
					}
				}
			}
		}
	}
}

func pathExistsInSecretConfigs(path []string, secrets []*SecretConfig) bool {
	found := false
path:
	for _, secret := range secrets {
		if secret.Name == path[0] {
			for _, key := range secret.Keys {
				if key.Name == path[1] {
					if len(path) == 2 {
						found = true
						break path
					}
					for _, alias := range key.AliasConfigs {
						if alias.Alias == path[2] {
							found = true
							break path
						}
					}
				}
			}
		}
	}

	return found
}
