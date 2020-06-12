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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecretAgentConfigurationSpec defines the desired state of SecretAgentConfiguration
type SecretAgentConfigurationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Required
	AppConfig AppConfig `json:"appConfig" yaml:"appConfig,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Secrets []*SecretConfig `json:"secrets" yaml:"secrets,omitempty" validate:"dive,unique=Name"`
}

// SecretAgentConfigurationStatus defines the observed state of SecretAgentConfiguration
type SecretAgentConfigurationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	TotalManagedObjects int      `json:"totalManagedObjects,omitempty"`
	ManagedK8sSecrets   []string `json:"managedK8sSecrets,omitempty"`
	ManagedAWSSecrets   []string `json:"managedAWSSecrets,omitempty"`
	ManagedGCPSecrets   []string `json:"managedGCPSecrets,omitempty"`
	ManagedAzureSecrets []string `json:"managedAzureSecrets,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=secretagentconfigurations,scope=Namespaced
// +kubebuilder:resource:shortName=sac
// +kubebuilder:printcolumn:name="TotalNumObjects",type="integer",JSONPath=".status.totalManagedObjects",description="Total no. of objects managed"
// +kubebuilder:printcolumn:name="K8sSecrets",type="string",priority=1,JSONPath=".status.managedK8sSecrets",description="All K8s managed secrets"

// SecretAgentConfiguration is the Schema for the secretagentconfigurations API
type SecretAgentConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretAgentConfigurationSpec   `json:"spec,omitempty"`
	Status SecretAgentConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecretAgentConfigurationList contains a list of SecretAgentConfiguration
type SecretAgentConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretAgentConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretAgentConfiguration{}, &SecretAgentConfigurationList{})
}

// SecretsManager Specifies which cloud secret manager will be used
// +kubebuilder:validation:Enum=none;GCP;AWS
type SecretsManager string

// Algorithm Specifies which keystore algorithm to use
// +kubebuilder:validation:Enum=ECDSAWithSHA256;SHA256WithRSA
type Algorithm string

// Algorithm strings
const (
	ECDSAWithSHA256 Algorithm = "ECDSAWithSHA256"
	SHA256WithRSA   Algorithm = "SHA256WithRSA"
)

// KeyConfigType Specifies which key type to use
// +kubebuilder:validation:Enum=literal;password;privateKey;publicKeySSH;ca;caPrivateKey;caCopy;pkcs12;jceks;jks
type KeyConfigType string

// AliasConfigType Specifies which alias config type to use
// +kubebuilder:validation:Enum=caCopy;keyPair;hmacKey;aesKey
type AliasConfigType string

// Key Config Type Strings
const (
	TypeLiteral      KeyConfigType = "literal"
	TypePassword     KeyConfigType = "password"
	TypePrivateKey   KeyConfigType = "privateKey"
	TypePublicKeySSH KeyConfigType = "publicKeySSH"
	TypeCA           KeyConfigType = "ca"
	TypeCAPrivateKey KeyConfigType = "caPrivateKey"
	TypeCACopy       KeyConfigType = "caCopy"
	TypePKCS12       KeyConfigType = "pkcs12"
	TypeJCEKS        KeyConfigType = "jceks"
	TypeJKS          KeyConfigType = "jks"
)

// Alias Config Type Strings
const (
	TypeCACopyAlias AliasConfigType = "caCopy"
	TypeKeyPair     AliasConfigType = "keyPair"
	TypeHMACKey     AliasConfigType = "hmacKey"
	TypeAESKey      AliasConfigType = "aesKey"
)

// SecretsManager Strings
const (
	SecretsManagerNone  SecretsManager = "none"
	SecretsManagerGCP   SecretsManager = "GCP"
	SecretsManagerAWS   SecretsManager = "AWS"
	SecretsManagerAzure SecretsManager = "Azure"
)

// AppConfig is the configuration for the forgeops-secrets application
type AppConfig struct {
	// +kubebuilder:validation:Required
	CreateKubernetesObjects bool `json:"createKubernetesObjects" yaml:"createKubernetesObjects"`
	// +kubebuilder:validation:Required
	SecretsManager SecretsManager `json:"secretsManager" yaml:"secretsManager,omitempty"`
	GCPProjectID   string         `json:"gcpProjectID,omitempty" yaml:"gcpProjectID,omitempty"`
	AWSRegion      string         `json:"awsRegion,omitempty" yaml:"awsRegion,omitempty"`
	AzureVaultName string         `json:"azureVaultName,omitempty" yaml:"azureVaultName,omitempty"`
}

// SecretConfig is the configuration for a specific Kubernetes secret
type SecretConfig struct {
	// +kubebuilder:validation:Required
	Name      string `json:"name" yaml:"name,omitempty"`
	Namespace string `json:"-" yaml:"namespace,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Keys []*KeyConfig `json:"keys" yaml:"keys,omitempty" validate:"dive,unique=Name"`
}

// KeyConfig is the configuration for a specific data key
type KeyConfig struct {
	// +kubebuilder:validation:Required
	Name string `json:"name" yaml:"name,omitempty"`
	// +kubebuilder:validation:Required
	Type           KeyConfigType  `json:"type" yaml:"type,omitempty"`
	Value          string         `json:"value,omitempty" yaml:"value,omitempty"`
	Length         int            `json:"length,omitempty" yaml:"length,omitempty"`
	CAPath         []string       `json:"caPath,omitempty" yaml:"caPath,omitempty"`
	PrivateKeyPath []string       `json:"privateKeyPath,omitempty" yaml:"privateKeyPath,omitempty"`
	StorePassPath  []string       `json:"storePassPath,omitempty" yaml:"storePassPath,omitempty"`
	KeyPassPath    []string       `json:"keyPassPath,omitempty" yaml:"keyPassPath,omitempty"`
	AliasConfigs   []*AliasConfig `json:"keystoreAliases,omitempty" yaml:"keystoreAliases,omitempty,omitempty"`
	Node           *Node          `json:"-" yaml:"node,omitempty"`
}

// AliasConfig is the configuration for a keystore alias
type AliasConfig struct {
	// +kubebuilder:validation:Required
	Alias string `json:"alias" yaml:"alias,omitempty"`
	// +kubebuilder:validation:Required
	Type           AliasConfigType `json:"type" yaml:"type,omitempty"`
	Algorithm      Algorithm       `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	CommonName     string          `json:"commonName,omitempty" yaml:"commonName,omitempty"`
	Sans           []string        `json:"sans,omitempty" yaml:"sans,omitempty"`
	SignedWithPath []string        `json:"signedWithPath,omitempty" yaml:"signedWithPath,omitempty"`
	SharedCert     bool            `json:"sharedCert,omitempty" yaml:"sharedCert,omitempty"`
	CAPath         []string        `json:"caPath,omitempty" yaml:"caPath,omitempty"`
	Node           *Node           `json:"-" yaml:"node,omitempty"`
}

// Node is a dependency tree branch or leaf
// Path is of form secret Name, data Key, and keystore Alias if exists
type Node struct {
	Path         []string      `yaml:"path,omitempty"`
	Parents      []*Node       `yaml:"parents,omitempty"`
	Children     []*Node       `yaml:"children,omitempty"`
	SecretConfig *SecretConfig `yaml:"secretConfig,omitempty"`
	KeyConfig    *KeyConfig    `yaml:"keyConfig,omitempty"`
	AliasConfig  *AliasConfig  `yaml:"aliasConfig,omitempty"`
	Value        []byte        `yaml:"value,omitempty"`
}
