package k8ssecrets

import (
	"context"
	"reflect"

	// Allow kubeconfig auth providers such as "GCP"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// LoadExisting loads any existing secrets in the Kubernetes API into the memory store
func LoadExisting(rclient client.Client, secretsConfig []*v1alpha1.SecretConfig) error {
	for _, secretConfig := range secretsConfig {

		k8sSecret := &corev1.Secret{}
		if err := rclient.Get(context.TODO(), types.NamespacedName{Name: secretConfig.Name, Namespace: secretConfig.Namespace}, k8sSecret); err != nil {
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
				keyConfig.Node.Value = value
			}
		}
	}

	return nil
}

// ApplySecrets applies secrets from the memory store into the Kubernetes API
func ApplySecrets(rclient client.Client, secret *corev1.Secret) (string, error) {
	var operation string
	// apply
	found := &corev1.Secret{}
	if err := rclient.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found); err != nil {
		if k8sErrors.IsNotFound(err) {
			// create
			if err := rclient.Create(context.TODO(), secret); err != nil {
				return "", errors.WithStack(err)
			}
			operation = "Created"
		} else {
			return "", errors.WithStack(err)
		}

	} else {
		//secret found, check if we need to update
		if !reflect.DeepEqual(secret.Data, found.Data) {
			if err := rclient.Update(context.TODO(), secret); err != nil {
				return "", errors.WithStack(err)
			}
			operation = "Updated"
		} else {
			//Nothing happened
			return "", nil
		}

	}

	return operation, nil
}

// GenerateSecretAPIObjects generates a list of secrets references that can be used to target the Kubernetes API
func GenerateSecretAPIObjects(secretConfig *v1alpha1.SecretConfig) *corev1.Secret {
	// prepare Kubernetes Secret
	k8sSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretConfig.Name, Namespace: secretConfig.Namespace},
		Data:       map[string][]byte{},
	}
	for _, keyConfig := range secretConfig.Keys {
		k8sSecret.Data[keyConfig.Name] = keyConfig.Node.Value
	}
	return k8sSecret

}
