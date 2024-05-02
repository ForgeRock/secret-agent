// +build integration

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
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// These tests are written in BDD-style using Ginkgo framework. Refer to
// http://onsi.github.io/ginkgo to learn more.

var _ = Describe("SecretAgentConfiguration", func() {
	var (
		key              types.NamespacedName
		created, fetched *SecretAgentConfiguration
	)

	BeforeEach(func() {
		// Add any setup steps that needs to be executed before each test
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	// Add Tests for OpenAPI validation (or additional CRD features) specified in
	// your API definition.
	// Avoid adding tests for vanilla CRUD operations because they would
	// test Kubernetes API server, which isn't the goal here.
	Context("Create API", func() {

		It("should create an object successfully", func() {

			key = types.NamespacedName{
				Name:      "foo",
				Namespace: "default",
			}
			created = &SecretAgentConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "default",
				},
				Spec: SecretAgentConfigurationSpec{
					AppConfig: AppConfig{
						CreateKubernetesObjects: false,
						SecretsManager:          "none",
					},
					Secrets: []*SecretConfig{
						{
							Name: "testkeyLiteral",
							Keys: []*KeyConfig{
								{
									Name: "username",
									Type: "literal",
									Spec: &KeySpec{
										Value: "literal",
									},
								},
							},
						},
						{
							Name: "testkeyPassword",
							Keys: []*KeyConfig{
								{
									Name: "pwd",
									Type: "password",
									Spec: &KeySpec{
										Length: new(int),
									},
								},
							},
						},
						{
							Name: "testkeySSH",
							Keys: []*KeyConfig{
								{
									Name: "ssh",
									Type: "ssh",
									Spec: &KeySpec{},
								},
							},
						},
						{
							Name: "testkeyCA",
							Keys: []*KeyConfig{
								{
									Name: "ca",
									Type: "ca",
									Spec: &KeySpec{
										DistinguishedName: &DistinguishedName{
											CommonName: "foobar",
										},
									},
								},
							},
						},
						{
							Name: "testkeyKeyPair",
							Keys: []*KeyConfig{
								{
									Name: "kp",
									Type: "keyPair",
									Spec: &KeySpec{
										Algorithm: "ECDSAWithSHA256",
										DistinguishedName: &DistinguishedName{
											CommonName: "foobar",
										},
										Sans:           []string{"foo", "bar"},
										SignedWithPath: "path/1",
									},
								},
							},
						},
						{
							Name: "testkeyTruststore",
							Keys: []*KeyConfig{
								{
									Name: "pwd",
									Type: "password",
									Spec: &KeySpec{
										TruststoreImportPaths: []string{"path/1", "path/2"},
									},
								},
							},
						},
						{
							Name: "testkeyKeytool",
							Keys: []*KeyConfig{
								{
									Name: "kt",
									Type: "keytool",
									Spec: &KeySpec{
										StoreType:     "jceks",
										StorePassPath: "path/1",
										KeyPassPath:   "path/2",
										KeytoolAliases: []*KeytoolAliasConfig{
											{
												Name: "name1",
												Cmd:  "genkeypair",
												Args: []string{"arg1", "arg2"},
											},
											{
												Name:       "name2",
												Cmd:        "importcert",
												SourcePath: "path/4",
											},
										},
									},
								},
							},
						},
					},
				},
			}

			By("creating an API obj")
			Expect(k8sClient.Create(context.Background(), created)).To(Succeed())

			fetched = &SecretAgentConfiguration{}
			Expect(k8sClient.Get(context.Background(), key, fetched)).To(Succeed())
			Expect(fetched).To(Equal(created))

			By("deleting the created object")
			Expect(k8sClient.Delete(context.Background(), created)).To(Succeed())
			Expect(k8sClient.Get(context.Background(), key, created)).ToNot(Succeed())
		})

	})
})
