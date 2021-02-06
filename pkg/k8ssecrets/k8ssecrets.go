package k8ssecrets

import (
	"context"
	"reflect"

	// Allow kubeconfig auth providers such as "GCP"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// LoadSecret loads any existing secrets in the Kubernetes API into the memory store
func LoadSecret(rclient client.Client, secretName, namespace string) (*corev1.Secret, error) {
	k8sSecret := &corev1.Secret{}
	if err := rclient.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: namespace}, k8sSecret); err != nil {
		if k8sErrors.IsNotFound(err) {
			meta := metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			}
			return &corev1.Secret{
				ObjectMeta: meta,
			}, err
		}
		return k8sSecret, errors.WithStack(err)
	}
	return k8sSecret, nil

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

// DeleteSecret deletes the secret from the Kubernetes API
func DeleteSecret(rclient client.Client, secretName, namespace string) (*corev1.Secret, error) {
	k8sSecret, err := LoadSecret(rclient, secretName, namespace)
	if err != nil {
		return k8sSecret, err
	}
	err = rclient.Delete(context.TODO(), k8sSecret, client.PropagationPolicy("Background"))
	return k8sSecret, nil
}
