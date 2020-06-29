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
	AppConfig AppConfig `json:"appConfig"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Secrets []*SecretConfig `json:"secrets" validate:"dive,unique=Name"`
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

// DistinguishedName certificate subject data
type DistinguishedName struct {
	Country            []string `json:"country,omitempty" yaml:"country,omitempty"`
	Organization       []string `json:"organization,omitempty" yaml:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationUnit,omitempty" yaml:"organizationUnit,omitempty"`
	Locality           []string `json:"locality,omitempty" yaml:"locality,omitempty"`
	Province           []string `json:"province,omitempty" yaml:"province,omitempty"`
	StreetAddress      []string `json:"streetAddress,omitempty" yaml:"streetAddress,omitempty"`
	PostalCode         []string `json:"postalCode,omitempty" yaml:"postalCode,omitempty"`
	SerialNumber       string   `json:"serialNumber,omitempty" yaml:"serialNumber,omitempty"`
	CommonName         string   `json:"commonName,omitempty" yaml:"commonName,omitempty,flow"`
}

func (dn *DistinguishedName) isEmpty() bool {
	if len(dn.Country) != 0 {
		return true
	}
	if len(dn.Organization) != 0 {
		return true
	}
	if len(dn.OrganizationalUnit) != 0 {
		return true
	}
	if len(dn.Locality) != 0 {
		return true
	}
	if len(dn.Province) != 0 {
		return true
	}
	if len(dn.StreetAddress) != 0 {
		return true
	}
	if len(dn.PostalCode) != 0 {
		return true
	}
	if dn.SerialNumber == "" {
		return true
	}
	if dn.CommonName == "" {
		return true
	}
	return false
}

func init() {
	SchemeBuilder.Register(&SecretAgentConfiguration{}, &SecretAgentConfigurationList{})
}

const (
	// PathDelimiter is used for reference paths in the SecretAgentConfiguration
	PathDelimiter string = "/"
)

// SecretsManager Specifies which cloud secret manager will be used
// +kubebuilder:validation:Enum=none;GCP;AWS
type SecretsManager string

// SecretsManager Strings
const (
	SecretsManagerNone  SecretsManager = "none"
	SecretsManagerGCP   SecretsManager = "GCP"
	SecretsManagerAWS   SecretsManager = "AWS"
	SecretsManagerAzure SecretsManager = "Azure"
)

// AlgorithmType Specifies which keystore algorithm to use
// +kubebuilder:validation:Enum=ECDSAWithSHA256;SHA256WithRSA
type AlgorithmType string

// AlgorithmType strings
const (
	AlgorithmTypeECDSAWithSHA256 AlgorithmType = "ECDSAWithSHA256"
	AlgorithmTypeSHA256WithRSA   AlgorithmType = "SHA256WithRSA"
)

// StoreType Specifies which keystore store type to use
// +kubebuilder:validation:Enum=pkcs12;jceks;jks
type StoreType string

// StoreType strings
const (
	StoreTypePkcs12 StoreType = "pkcs12"
	StoreTypeJceks  StoreType = "jceks"
	StoreTypeJks    StoreType = "jks"
)

// KeyConfigType Specifies which key type to use
// +kubebuilder:validation:Enum=ca;literal;password;ssh;keyPair;truststore;keytool;
type KeyConfigType string

// Key Config Type Strings
const (
	KeyConfigTypeCA         KeyConfigType = "ca"
	KeyConfigTypeLiteral    KeyConfigType = "literal"
	KeyConfigTypePassword   KeyConfigType = "password"
	KeyConfigTypeSSH        KeyConfigType = "ssh"
	KeyConfigTypeKeyPair    KeyConfigType = "keyPair"
	KeyConfigTypeTrustStore KeyConfigType = "truststore"
	KeyConfigTypeKeytool    KeyConfigType = "keytool"
)

// KeytoolCmd Specifies the keytool command to use.
// +kubebuilder:validation:Enum=genkeypair;genseckey;importcert;importpassword
type KeytoolCmd string

// Key Config Type Strings
const (
	KeytoolCmdGenkeypair     KeytoolCmd = "genkeypair"
	KeytoolCmdGenseckey      KeytoolCmd = "genseckey"
	KeytoolCmdImportcert     KeytoolCmd = "importcert"
	KeytoolCmdImportpassword KeytoolCmd = "importpassword"
)

// AppConfig is the configuration for the forgeops-secrets application
type AppConfig struct {
	// +kubebuilder:validation:Required
	CreateKubernetesObjects bool `json:"createKubernetesObjects"`
	// +kubebuilder:validation:Required
	SecretsManager SecretsManager `json:"secretsManager"`
	GCPProjectID   string         `json:"gcpProjectID,omitempty"`
	AWSRegion      string         `json:"awsRegion,omitempty"`
	AzureVaultName string         `json:"azureVaultName,omitempty"`

	// Optional number of times the operator will attempt to generate secrets. Defaults to 3
	MaxRetries *int `json:"maxRetries,omitempty"`

	// Optional backoff time in seconds before retrying secret generation. Defaults to 2
	BackOffSecs *int `json:"backOffSecs,omitempty"`
}

// SecretConfig is the configuration for a specific Kubernetes secret
type SecretConfig struct {
	// +kubebuilder:validation:Required
	Name      string `json:"name"`
	Namespace string `json:"-"`

	// This flag tells the controller to generate the secret only if the controller can't find it in k8s or the secret manager.
	// This is useful if the user wants to enforce the use of the provided secret and avoid ever generating new ones.
	// Defaults to true.
	GenerateIfNecessary *bool `json:"generateIfNecessary,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Keys []*KeyConfig `json:"keys" validate:"dive,unique=Name"`
}

// KeyConfig is the configuration for a specific data key
type KeyConfig struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	Type KeyConfigType `json:"type"`
	Spec *KeySpec      `json:"spec,omitempty"`

	// TODO Delete all items below this line
	Value          string         `json:"value,omitempty"`
	Length         int            `json:"length,omitempty"`
	CAPath         []string       `json:"caPath,omitempty"`
	PrivateKeyPath []string       `json:"privateKeyPath,omitempty"`
	StorePassPath  []string       `json:"storePassPath,omitempty"`
	KeyPassPath    []string       `json:"keyPassPath,omitempty"`
	AliasConfigs   []*AliasConfig `json:"keystoreAliases,omitempty"`
	Node           *Node          `json:"-"`
}

// KeySpec is the configuration for each key
type KeySpec struct {
	Value                 string             `json:"value,omitempty"`
	Algorithm             AlgorithmType      `json:"algorithm,omitempty"`
	DistinguishedName     *DistinguishedName `json:"distinguishedName,omitempty"`
	SignedWithPath        string             `json:"signedWithPath,omitempty"`
	StoreType             StoreType          `json:"storeType,omitempty"`
	StorePassPath         string             `json:"storePassPath,omitempty"`
	KeyPassPath           string             `json:"keyPassPath,omitempty"`
	Sans                  []string           `json:"sans,omitempty"`
	TruststoreImportPaths []string           `json:"truststoreImportPaths,omitempty"`

	// +kubebuilder:validation:Minimun=16
	Length *int `json:"length,omitempty"`

	// +kubebuilder:validation:MinItems=1
	KeytoolAliases []*KeytoolAliasConfig `json:"keytoolAliases,omitempty" validate:"dive,unique=Name"`
}

// KeytoolAliasConfig is the configuration for a keystore alias
type KeytoolAliasConfig struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	Cmd             KeytoolCmd `json:"cmd"`
	Args            []string   `json:"args,omitempty"`
	SourcePath      string     `json:"sourcePath,omitempty"`
	DestinationPath string     `json:"destinationPath,omitempty"`
}

// TODO
/////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
//// EVERYTHING BELOW THIS LINE IS UP FOR THE CHOPPING BLOCK////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////

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
	SelfSigned     bool            `json:"selfSigned,omitempty" yaml:"selfSigned,omitempty"`
	Expire         int             `json:"expire,omitempty" yaml:"expire,omitempty"`
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
	TypeTrustStore   KeyConfigType = "truststore"
)

// AliasConfigType Specifies which alias config type to use
// +kubebuilder:validation:Enum=caCopy;keyPair;hmacKey;aesKey
type AliasConfigType string

// Alias Config Type Strings
const (
	TypeCACopyAlias AliasConfigType = "caCopy"
	TypeKeyPair     AliasConfigType = "keyPair"
	TypeHMACKey     AliasConfigType = "hmacKey"
	TypeAESKey      AliasConfigType = "aesKey"
)

// Algorithm Specifies which keystore algorithm to use
// +kubebuilder:validation:Enum=ECDSAWithSHA256;SHA256WithRSA
type Algorithm string

// Algorithm strings
const (
	ECDSAWithSHA256 Algorithm = "ECDSAWithSHA256"
	SHA256WithRSA   Algorithm = "SHA256WithRSA"
)
