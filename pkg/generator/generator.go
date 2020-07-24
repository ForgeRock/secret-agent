package generator

import (
	"context"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

const (
	defaultPasswordLength = 20
)

// KeyMgr an interface for managing secret data
type KeyMgr interface {
	References() ([]string, []string)
	LoadReferenceData(data map[string][]byte) error
	LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error
	EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error
	Generate() error
	LoadFromData(secData map[string][]byte)
	IsEmpty() bool
	ToKubernetes(secObject *corev1.Secret)
	InSecret(secObject *corev1.Secret) bool
}
