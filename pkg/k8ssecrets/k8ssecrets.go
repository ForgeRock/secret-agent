package k8ssecrets

import (
	"bytes"
	"encoding/base64"
	"flag"

	// Allow kubeconfig auth providers such as "GCP"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/pkg/errors"
	k8sApiv1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"github.com/ForgeRock/secret-agent/pkg/types"
)

var (
	kubeConfig = flag.String("kubeConfig", "", "path to the kubeconfig file, leave blank to use InClusterConfig")
)

// LoadExisting loads any existing secrets in the Kubernetes API into the memory store
func LoadExisting(clientSet kubernetes.Interface, secretsConfig []*types.SecretConfig) error {
	for _, secretConfig := range secretsConfig {
		k8sSecret, err := clientSet.CoreV1().Secrets(secretConfig.Namespace).
			Get(secretConfig.Name, metav1.GetOptions{})
		if err != nil {
			if k8sErrors.IsNotFound(err) {
				continue
			}
			return errors.WithStack(err)
		}
		for _, keyConfig := range secretConfig.Keys {
			// only load from Kubernetes if not in memory store (node.Value),
			//   since SecretsManager is source of truth if in use
			if len(keyConfig.Node.Value) != 0 {
				continue
			}
			if value, exists := k8sSecret.Data[keyConfig.Name]; exists {
				decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
				_, err = base64.StdEncoding.Decode(decoded, value)
				if err != nil {
					return err
				}
				decoded = bytes.Trim(decoded, "\x00")
				keyConfig.Node.Value = decoded
			}
		}
	}

	return nil
}

// ApplySecrets applies secrets from the memory store into the Kubernetes API
func ApplySecrets(clientSet kubernetes.Interface, secretsConfig []*types.SecretConfig) error {
	for _, secretConfig := range secretsConfig {
		// prepare Kubernetes Secret
		k8sSecret := &k8sApiv1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretConfig.Name, Namespace: secretConfig.Namespace},
			Data:       map[string][]byte{},
		}
		for _, keyConfig := range secretConfig.Keys {
			encoded := make([]byte, base64.StdEncoding.EncodedLen(len(keyConfig.Node.Value)))
			base64.StdEncoding.Encode(encoded, keyConfig.Node.Value)
			k8sSecret.Data[keyConfig.Name] = encoded
		}

		// apply
		_, err := clientSet.CoreV1().Secrets(secretConfig.Namespace).
			Get(secretConfig.Name, metav1.GetOptions{})
		if err != nil {
			if k8sErrors.IsNotFound(err) {
				// create
				_, err := clientSet.CoreV1().Secrets(secretConfig.Namespace).Create(k8sSecret)
				if err != nil {
					return errors.WithStack(err)
				}
			} else {
				return errors.WithStack(err)
			}
		}
		// update
		_, err = clientSet.CoreV1().Secrets(secretConfig.Namespace).Update(k8sSecret)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// GetClientSet gets an InClusterConfig or kubeconfig ClientSet depending on flag
func GetClientSet() (*kubernetes.Clientset, error) {
	clientSet := &kubernetes.Clientset{}
	config := &rest.Config{}
	if *kubeConfig != "" {
		c, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
		if err != nil {
			return clientSet, errors.WithStack(err)
		}
		config = c
	} else {
		c, err := rest.InClusterConfig()
		if err != nil {
			return clientSet, errors.WithStack(err)
		}
		config = c
	}

	return kubernetes.NewForConfig(config)
}
