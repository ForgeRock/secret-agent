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

	AppConfig AppConfig       `yaml:"appConfig" json:"appConfig" validate:"required,dive,required"`
	Secrets   []*SecretConfig `yaml:"secrets" json:"secrets" validate:"dive,required,unique=Name,gt=0,dive,required"`
}

// SecretAgentConfigurationStatus defines the observed state of SecretAgentConfiguration
type SecretAgentConfigurationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	TotalManagedObjects int      `yaml:"totalManagedObjects,omitempty" json:"totalManagedObjects,omitempty"`
	ManagedK8sSecrets   []string `yaml:"managedK8sSecrets,omitempty" json:"managedK8sSecrets,omitempty"`
	ManagedAWSSecrets   []string `yaml:"managedAWSSecrets,omitempty" json:"managedAWSSecrets,omitempty"`
	ManagedGCPSecrets   []string `yaml:"managedGCPSecrets,omitempty" json:"managedGCPSecrets,omitempty"`
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
// Only one of the following secrets manager may be specified.
// +kubebuilder:validation:Enum=none;GCP;AWS
type SecretsManager string

// Algorithm Specifies which keystore algorithm to use
// Only one of the following algorithms may be specified.
// +kubebuilder:validation:Enum=ECDSAWithSHA256;SHA256withRSA
type Algorithm string

// KeyConfigType Specifies which key type to use
// Only one of the following types may be specified.
// +kubebuilder:validation:Enum=literal;password;privateKey;publicKeySSH;jceks;pkcs12;jks
type KeyConfigType string

// AliasConfigType Specifies which alias config type to use
// Only one of the following types may be specified.
// +kubebuilder:validation:Enum=ca;keyPair;hmacKey;aesKey
type AliasConfigType string

// Key Config Type Strings
const (
	TypeLiteral      KeyConfigType = "literal"
	TypePassword     KeyConfigType = "password"
	TypePrivateKey   KeyConfigType = "privateKey"
	TypePublicKeySSH KeyConfigType = "publicKeySSH"
	TypeJCEKS        KeyConfigType = "jceks"
	TypePKCS12       KeyConfigType = "pkcs12"
	TypeJKS          KeyConfigType = "jks"
)

// Alias Config Type Strings
const (
	TypeCA      AliasConfigType = "ca"
	TypeKeyPair AliasConfigType = "keyPair"
	TypeHmacKey AliasConfigType = "hmacKey"
	TypeAESKey  AliasConfigType = "aesKey"
)

// SecretsManager Strings
const (
	SecretsManagerNone SecretsManager = "none"
	SecretsManagerGCP  SecretsManager = "GCP"
	SecretsManagerAWS  SecretsManager = "AWS"
)

// AppConfig is the configuration for the forgeops-secrets application
type AppConfig struct {
	CreateKubernetesObjects bool           `yaml:"createKubernetesObjects" json:"createKubernetesObjects"`
	SecretsManager          SecretsManager `yaml:"secretsManager" json:"secretsManager" validate:"required,oneof=none GCP AWS"`
	GCPProjectID            string         `yaml:"gcpProjectID" json:"gcpProjectID,omitempty"`
	AWSRegion               string         `yaml:"awsRegion" json:"awsRegion,omitempty"`
}

// Configuration is the configuration for the forgeops-secrets application
//   and the secrets it manages
type Configuration struct {
	AppConfig AppConfig `yaml:"appConfig" json:"appConfig" validate:"required,dive,required"`
	// +kubebuilder:validation:MinItems=1
	Secrets []*SecretConfig `yaml:"secrets" json:"secrets" validate:"dive,required,unique=Name,gt=0,dive,required"`
}

// SecretConfig is the configuration for a specific Kubernetes secret
type SecretConfig struct {
	Name      string `yaml:"name" json:"name" validate:"required"`
	Namespace string `yaml:"-" json:"-"`
	// +kubebuilder:validation:MinItems=1
	Keys []*KeyConfig `yaml:"keys" json:"keys" validate:"dive,required,unique=Name,gt=0,dive,required"`
}

// KeyConfig is the configuration for a specific data key
type KeyConfig struct {
	Name           string         `yaml:"name" json:"name" validate:"required"`
	Type           KeyConfigType  `yaml:"type" json:"type" validate:"required,oneof=jceks literal password privateKey publicKeySSH pkcs12 jks jceks"`
	Value          string         `yaml:"value,omitempty" json:"value,omitempty"`
	Length         int            `yaml:"length,omitempty" json:"length,omitempty"`
	PrivateKeyPath []string       `yaml:"privateKeyPath,omitempty" json:"privateKeyPath,omitempty"`
	StorePassPath  []string       `yaml:"storePassPath,omitempty" json:"storePassPath,omitempty"`
	KeyPassPath    []string       `yaml:"keyPassPath,omitempty" json:"keyPassPath,omitempty"`
	AliasConfigs   []*AliasConfig `yaml:"keystoreAliases,omitempty" json:"keystoreAliases,omitempty" validate:"dive"`
	Node           *Node          `json:"-"`
}

// AliasConfig is the configuration for a keystore alias
type AliasConfig struct {
	Alias          string          `yaml:"alias" json:"alias" validate:"required"`
	Type           AliasConfigType `yaml:"type"  json:"type" validate:"required,oneof=ca keyPair hmacKey aesKey"`
	Algorithm      Algorithm       `yaml:"algorithm" json:"algorithm" validate:"oneof='' ECDSAWithSHA256 SHA256withRSA"`
	CommonName     string          `yaml:"commonName" json:"commonName"`
	Sans           []string        `yaml:"sans" json:"sans,omitempty"`
	SignedWithPath []string        `yaml:"signedWithPath" json:"signedWithPath,omitempty"`
	PasswordPath   []string        `yaml:"passwordPath" json:"passwordPath,omitempty"`
	Node           *Node           `json:"-"`
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
