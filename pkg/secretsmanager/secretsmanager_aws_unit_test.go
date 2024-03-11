/*
Ideally we would want to be testing this from the outside but would need to change some methods to public

package secretsmanager_test
*/
package secretsmanager

import (
	"context"
	"testing"

	awssecretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
	"github.com/go-logr/logr"
)

type mockSecretsApi struct {
	// GetSecretValue(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error)
	get    func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error)
	create func(ctx context.Context, params *awssecretsmanager.CreateSecretInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.CreateSecretOutput, error)
	put    func(ctx context.Context, params *awssecretsmanager.PutSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.PutSecretValueOutput, error)
}

func (m mockSecretsApi) GetSecretValue(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
	return m.get(ctx, params, optFns...)
}

func (m mockSecretsApi) PutSecretValue(ctx context.Context, params *awssecretsmanager.PutSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.PutSecretValueOutput, error) {
	return m.put(ctx, params, optFns...)
}

func (m mockSecretsApi) CreateSecret(ctx context.Context, params *awssecretsmanager.CreateSecretInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.CreateSecretOutput, error) {
	return m.create(ctx, params, optFns...)
}

func Test_Ensure_secret_AWS_SM_succeeds(t *testing.T) {

	ttests := map[string]struct {
		awsSecretsApi func(t *testing.T) secretsMgrApi
		awsSecretName string
		awsSecretVal  []byte
	}{
		"when secret exists": {
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return &awssecretsmanager.GetSecretValueOutput{}, nil
				}
				return mSecApi
			},
		},
		"when secret does not exist and is successfully created and value is set": {
			awsSecretName: "bar",
			awsSecretVal:  []byte(`foo`),
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				}
				mSecApi.put = func(ctx context.Context, params *awssecretsmanager.PutSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.PutSecretValueOutput, error) {
					if *params.SecretId != "bar" {
						t.Errorf("incorrect secretId passed: got (%s), wanted: bar", *params.SecretId)
					}
					if string(params.SecretBinary) != "foo" {
						t.Errorf("incorrect secretValus passed: got (%s), wanted: foo", string(params.SecretBinary))
					}
					return &awssecretsmanager.PutSecretValueOutput{}, nil
				}
				mSecApi.create = func(ctx context.Context, params *awssecretsmanager.CreateSecretInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.CreateSecretOutput, error) {
					if *params.Name != "bar" {
						t.Errorf("incorrect secretId passed: got (%s), wanted: bar", *params.Name)
					}
					return &awssecretsmanager.CreateSecretOutput{}, nil
				}
				return mSecApi
			},
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			awsSecMgr := &secretManagerAWS{
				log:    logr.Logger{},
				client: tt.awsSecretsApi(t),
			}
			err := awsSecMgr.EnsureSecret(context.TODO(), tt.awsSecretName, tt.awsSecretVal)
			if err != nil {
				t.Errorf("EnsureSecret got (%s), wanted <nil>", err.Error())
			}
		})
	}
}

func Test_EnsureSecret_should_fail(t *testing.T) {
	ttests := map[string]struct {
		awsSecretsApi func(t *testing.T) secretsMgrApi
		awsSecretName string
		awsSecretVal  []byte
		errorTyp      error
	}{
		"when fetching a secret": {
			errorTyp:      &smithy.OperationError{},
			awsSecretVal:  []byte(`foo`),
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &smithy.OperationError{}
				}
				return mSecApi
			},
		},
		"when secret does not exist and errors on create": {
			errorTyp:      &smithy.OperationError{},
			awsSecretVal:  []byte(`foo`),
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				}
				mSecApi.create = func(ctx context.Context, params *awssecretsmanager.CreateSecretInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.CreateSecretOutput, error) {
					if *params.Name != "bar" {
						t.Errorf("incorrect secretId passed: got (%s), wanted: bar", *params.Name)
					}
					return nil, &smithy.OperationError{}
				}
				return mSecApi
			},
		},
		"when secret exists but errors on put value": {
			errorTyp:      &smithy.OperationError{},
			awsSecretVal:  []byte(`foo`),
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				}
				mSecApi.create = func(ctx context.Context, params *awssecretsmanager.CreateSecretInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.CreateSecretOutput, error) {
					if *params.Name != "bar" {
						t.Errorf("incorrect secretId passed: got (%s), wanted: bar", *params.Name)
					}
					return &awssecretsmanager.CreateSecretOutput{}, nil
				}
				mSecApi.put = func(ctx context.Context, params *awssecretsmanager.PutSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.PutSecretValueOutput, error) {
					if *params.SecretId != "bar" {
						t.Errorf("incorrect secretId passed: got (%s), wanted: bar", *params.SecretId)
					}
					if string(params.SecretBinary) != "foo" {
						t.Errorf("incorrect secretValus passed: got (%s), wanted: foo", string(params.SecretBinary))
					}
					return nil, &smithy.OperationError{}
				}
				return mSecApi
			},
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			awsSecMgr := &secretManagerAWS{
				log:    logr.Logger{},
				client: tt.awsSecretsApi(t),
			}
			err := awsSecMgr.EnsureSecret(context.TODO(), tt.awsSecretName, tt.awsSecretVal)
			if err == nil {
				t.Errorf("got <nil>, wanted %s", tt.errorTyp)
			}
		})
	}
}

// test load secrets

func Test_LoadSecret_should_succeed(t *testing.T) {
	ttests := map[string]struct {
		awsSecretsApi func(t *testing.T) secretsMgrApi
		awsSecretName string
		awsSecretVal  []byte
	}{
		"when fetching a secret and it does not exist": {
			awsSecretVal:  []byte(`secret`),
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return &awssecretsmanager.GetSecretValueOutput{SecretBinary: []byte(`secret`)}, nil
				}
				return mSecApi
			},
		},
		"when fetching a secret and it exists": {
			awsSecretVal:  nil,
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				}
				return mSecApi
			},
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			awsSecMgr := &secretManagerAWS{
				log:    logr.Logger{},
				client: tt.awsSecretsApi(t),
			}
			got, err := awsSecMgr.LoadSecret(context.TODO(), tt.awsSecretName)
			if err != nil {
				t.Errorf("LoadSecret got %s, wanted <nil>\n", err)
			}
			if string(got) != string(tt.awsSecretVal) {
				t.Errorf("LoadSecret got %s, wanted %s\n", got, tt.awsSecretVal)
			}
		})
	}
}

func Test_LoadSecret_should_fail(t *testing.T) {
	ttests := map[string]struct {
		awsSecretsApi func(t *testing.T) secretsMgrApi
		awsSecretName string
		awsSecretVal  []byte
	}{
		"when fetching a secret - operation error": {
			awsSecretVal:  nil,
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &smithy.OperationError{}
				}
				return mSecApi
			},
		},
		"when fetching a secret - params error": {
			awsSecretVal:  nil,
			awsSecretName: "bar",
			awsSecretsApi: func(t *testing.T) secretsMgrApi {
				mSecApi := mockSecretsApi{}
				mSecApi.get = func(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error) {
					return nil, &smithy.InvalidParamsError{}
				}
				return mSecApi
			},
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			awsSecMgr := &secretManagerAWS{
				log:    logr.Logger{},
				client: tt.awsSecretsApi(t),
			}
			_, err := awsSecMgr.LoadSecret(context.TODO(), tt.awsSecretName)
			if err == nil {
				t.Errorf("LoadSecret got %s, wanted <nil>\n", err)
			}
		})
	}
}
