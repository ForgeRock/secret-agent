/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

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
