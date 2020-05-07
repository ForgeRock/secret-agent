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
	Algorithm      string   `yaml:"algorithm" validate:"required,oneof=ECDSAWithSHA256 SHA256withRSA"`
	CommonName     string   `yaml:"commonName" validate:"required"`
	Sans           []string `yaml:"sans"`
	SignedWithPath []string `yaml:"signedWithPath"`
	PasswordPath   []string `yaml:"passwordPath" validate:"required"`
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
			// if type literal, must have Value
			case TypeLiteral:
				if key.Value == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Value, "value", "Value", "literalValueEmpty", "")
				}
			// if type password, must have Length
			case TypePassword:
				if key.Length == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Length, "length", "Length", "passwordLengthZero", "")
				}
			// if type publicKeySSH, must have privateKey
			case TypePublicKeySSH:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				if len(key.PrivateKeyPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotSet", "")
					return
				}
				found := false
			privateKey:
				for _, s := range config.Secrets {
					if s.Name == key.PrivateKeyPath[0] {
						for _, k := range s.Keys {
							if k.Type == TypePrivateKey && k.Name == key.PrivateKeyPath[1] {
								found = true
								break privateKey
							}
						}
					}
				}
				if !found {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotFound", "")
				}
			// if type pkcs12, must have keystoreAliases
			case TypePKCS12:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				if len(key.AliasConfigs) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs, name, "AliasConfigs", "keystoreAliasesNotSet", "")
					return
				}
				for aliasIndex, alias := range key.AliasConfigs {
					switch alias.Type {
					// if type CA, must have passwordPath
					case TypeCA:
						name := fmt.Sprintf("Secrets.%s.%s.%s",
							config.Secrets[secretIndex].Name,
							config.Secrets[secretIndex].Keys[keyIndex].Name,
							config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias,
						)
						if len(alias.PasswordPath) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "CA", "passwordPathNotSet", "")
							return
						}
						found := false
					password:
						for _, s := range config.Secrets {
							if s.Name == alias.PasswordPath[0] {
								for _, k := range s.Keys {
									if k.Type == TypePassword && k.Name == alias.PasswordPath[1] {
										found = true
										break password
									}
								}
							}
						}
						if !found {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "CA", "passwordPathNotFound", "")
							return
						}
					}
				}
			}
		}
	}
}
