package generator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
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
	LoadSecretFromManager(context context.Context, sm secretsmanager.SecretManager, namespace, secretName string) error
	EnsureSecretManager(context context.Context, sm secretsmanager.SecretManager, namespace, secretName string) error
	Generate() error
	LoadFromData(secData map[string][]byte)
	IsEmpty() bool
	ToKubernetes(secObject *corev1.Secret)
	InSecret(secObject *corev1.Secret) bool
}

// GenConfig container for runtime secret object generation
type GenConfig struct {
	SecObject     *corev1.Secret
	Log           logr.Logger
	Namespace     string
	AppConfig     *v1alpha1.AppConfig
	KeysToGen     []*v1alpha1.KeyConfig
	Client        client.Client
	SecretManager secretsmanager.SecretManager
}

// KeyGenConfig container for runtime generation of keys
type keyGenConfig struct {
	keyMgr KeyMgr
	key    *v1alpha1.KeyConfig
	*GenConfig
}

// GenKeys load secrets from a secret manager or generate them and save to a secret manager
// GenKeys generates keys until there's an error or a dependency that can't be set.
func (g *GenConfig) GenKeys(ctx context.Context) error {
	// set timeout for generating each secret
	timeout := g.AppConfig.SecretTimeout

	keyCtx, cancel := context.WithTimeout(ctx, (time.Duration(*timeout) * time.Second))
	defer cancel()

	// only generate keys that dont exist in the secret
	keysNotInSecret := []*v1alpha1.KeyConfig{}
	for _, keyToGen := range g.KeysToGen {
		if _, ok := g.SecObject.Data[keyToGen.Name]; !ok {
			keysNotInSecret = append(keysNotInSecret, keyToGen)
		}
	}
	// keysToWork is all the keys that need to be generated
	keysToWork := append(g.KeysToGen[:0:0], keysNotInSecret...)
	// track the number of times we've tried to generate a key
	// attempts can't exceed the number of keys we are supposed to generate
	attempts := 0
	numberOfKeys := len(g.KeysToGen)
	for attempts < numberOfKeys {
		// make queue from keysToWork
		// queue is created on every attempt from keysToWork which contains only this keys that need to be generated
		queue := append(keysToWork[:0:0], keysToWork...)
		// set the bucket of work to 0, queue loop appends failure to this slice
		keysToWork = nil
		// process all keys in queue
		// queue loop
		for _, key := range queue {
			log := g.Log.WithValues(
				"data_key", key.Name,
				"secret_type", string(key.Type))
			log.V(1).Info("key processing started")
			keyGenerator, err := newKeyGenerator(key, g)
			if err != nil {
				return err
			}
			empty, err := keyGenerator.secretManagerHasData(keyCtx)
			if err != nil {
				log.Error(err, "skipping key")
				return err
			}
			// There's no secret data after checking, so get dependencies
			if empty {
				log.V(0).Info("secret needs to be generated")
				log.V(1).Info("gathering dependencies")
				completed, err := keyGenerator.configureDependencies(keyCtx)
				if k8serror.IsNotFound(err) {
					log.V(0).Info("has unmet dependencies will retry")
					return err
				} else if err != nil {
					log.Error(err, "error during dependecy resolution will retry")
					return err
				}
				// not completed loaded, we will try to run this key before returning
				if !completed {
					log.V(1).Info("trying to resolve dependency without a retry")
					keysToWork = append(keysToWork, key)
					continue
				}
			} else {
				log.V(0).Info("loaded from secret manager")
			}
			// Ensure Secret Manager and Secret Object are in a generated state
			if err := keyGenerator.syncKeys(ctx); err != nil {
				// return with a retry
				log.Error(err, "couldn't generate to secret manager, will retry")
				return err
			}
			log.V(1).Info("key completed")
		}
		attempts++
	}
	if attempts > numberOfKeys {
		return errors.Wrap(errNoRefFound, "maximum attempts to resolve a self reference has occured, are they all defined?")
	}
	g.Log.V(1).Info("completed all keys")
	return nil
}

// newKeyGenerator initialize a keygenconfig and key manager
// a key manager can throw an error on creation in some cases
// the error will occur when it can't initialize a temporary directory e.g. keytool
func newKeyGenerator(
	key *v1alpha1.KeyConfig,
	genConfig *GenConfig) (*keyGenConfig, error) {

	var keyInterface KeyMgr
	var err error
	switch key.Type {
	case v1alpha1.KeyConfigTypeCA:
		keyInterface = NewRootCA(key)
	case v1alpha1.KeyConfigTypeKeyPair:
		keyInterface, err = NewCertKeyPair(key)
		if err != nil {
			return &keyGenConfig{}, err
		}
	case v1alpha1.KeyConfigTypePassword:
		keyInterface = NewPassword(key)
	case v1alpha1.KeyConfigTypeLiteral:
		keyInterface = NewLiteral(key)
	case v1alpha1.KeyConfigTypeSSH:
		keyInterface = NewSSH(key)
	case v1alpha1.KeyConfigTypeKeytool:
		keyInterface, err = NewKeyTool(key)
		if err != nil {
			return &keyGenConfig{}, err
		}
	case v1alpha1.KeyConfigTypeTrustStore:
		keyInterface = NewTrustStore(key)
	default:
		return &keyGenConfig{}, errors.New("couldn't find key generator type")
	}
	return &keyGenConfig{
		keyInterface,
		key,
		genConfig,
	}, nil
}

// syncKeys Secret Object is updated to have secret data
// generates and writes data to secret manager  then to secret object
// only generate and write to secret manager if the key has no data
// a key will have data when it's loaded from a secret manager
func (k *keyGenConfig) syncKeys(ctx context.Context) error {
	log := k.Log.WithValues(
		"data_key", k.key.Name,
		"secret_type", string(k.key.Type))

	if !k.keyMgr.IsEmpty() {
		log.V(1).Info("secret data found, preparing k8s secret")
		// we don't need to do anything, just update the secret object
		k.keyMgr.ToKubernetes(k.SecObject)
		return nil
	}
	log.V(0).Info("generating")
	if err := k.keyMgr.Generate(); err != nil {
		log.Error(err, "failed to generate key")
		return err
	}
	if k.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone {
		err := k.keyMgr.EnsureSecretManager(ctx, k.SecretManager, k.Namespace, k.SecObject.Name)
		if err != nil {
			log.Error(err, "couldn't write to secret manager")
			return err
		}
		log.V(1).Info("added to secret manager")
	}
	log.V(1).Info("preparing k8s secret")
	k.keyMgr.ToKubernetes(k.SecObject)
	return nil
}

// configureDependencies tries to find all dependencies (references) and load them.
// true if all dependencies where found, false if not availble yet and error if not found
func (k *keyGenConfig) configureDependencies(ctx context.Context) (bool, error) {
	var err error = nil
	keyRefSecrets := make(map[string][]byte)
	var val []byte
	var ok bool

	log := k.Log.WithValues(
		"data_key", k.key.Name,
		"secret_type", string(k.key.Type))
	refs, refDataKeys := k.keyMgr.References()
	for index, ref := range refs {
		dataKey := refDataKeys[index]
		dataPath := fmt.Sprintf("%s/%s", ref, dataKey)
		log = log.WithValues("secret_ref", dataPath)
		selfReference := false
		secRefObject := &corev1.Secret{}

		// self referencing configuration
		if ref == k.SecObject.Name {
			secRefObject = k.SecObject
			selfReference = true
			// add reference data to map
			val, ok = secRefObject.Data[dataKey]
		} else if !k.AppConfig.CreateKubernetesObjects {
			val, err = k.loadRefFromManager(ctx, ref, dataKey)
			if err != nil {
				return false, err
			}
			ok = len(val) > 0
		} else {
			secRefObject, err = k8ssecrets.LoadSecret(k.Client, ref, k.Namespace)
			if k8serror.IsNotFound(err) {
				log.V(0).Info("reference not found")
				log.V(1).Info("skipping")
				return false, err
			} else if err != nil {
				log.Error(err, "error calling kubernetes api")
				return false, err
			}
			// add reference data to map
			val, ok = secRefObject.Data[dataKey]
		}

		if !ok && selfReference {
			// STOP a dependency does't exist but might exist after other keys are generated
			log.V(1).Info(fmt.Sprintf("missing self reference: %s", dataKey))
			return false, nil
		} else if !ok {
			// this is a secret that's missing a key
			log.Error(err, "secret ref data not found")
			return false, err
		}
		// added to map of reference data with a key value secretName/DataKey
		keyRefSecrets[dataPath] = val
	}
	// load refs into keymgr only when _all_ refs have been found
	if err := k.keyMgr.LoadReferenceData(keyRefSecrets); err != nil {
		log.Error(err, "error loading references skipping")
		return false, err
	}
	// all dependencies found and loaded
	return true, nil
}

// secretManagerHasData load from secret manager and determine if empty
func (k *keyGenConfig) secretManagerHasData(ctx context.Context) (bool, error) {
	log := k.Log.WithValues(
		"data_key", k.key.Name,
		"secret_type", string(k.key.Type))
	if k.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone {
		log.V(1).Info("loading secret from secret-manager")
		if err := k.keyMgr.LoadSecretFromManager(ctx, k.SecretManager, k.Namespace, k.SecObject.Name); err != nil {
			log.Error(err, "could not load secret from manager")
			return false, errors.Wrap(err, "failed api call to secret manager")
		}
	}
	return k.keyMgr.IsEmpty(), nil
}

// loadRefFromManager load ref from secret manager
func (k *keyGenConfig) loadRefFromManager(ctx context.Context, refName, refKey string) ([]byte, error) {
	nameFmt := fmt.Sprintf("%s_%s_%s", k.Namespace, refName, refKey)
	value, err := k.SecretManager.LoadSecret(ctx, nameFmt)
	if err != nil {
		return []byte{}, err
	}
	return value, err
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
