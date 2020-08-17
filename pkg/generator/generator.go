package generator

import (
	"context"
	"strings"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
)

const (
	defaultPasswordLength = 20
)

var (
	errRefPath    error = errors.New("reference path should be exactly a secret name and a data key")
	errNoRefPath  error = errors.New("no ref path found")
	errNoRefFound error = errors.New("no reference data found")
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

func handleRefPath(path string) (string, string) {
	if path != "" {
		paths := strings.Split(path, "/")
		if len(paths) != 2 {
			return "", ""
		}
		return paths[0], paths[1]
	}
	return "", ""
}
