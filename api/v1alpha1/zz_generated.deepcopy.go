// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AliasConfig) DeepCopyInto(out *AliasConfig) {
	*out = *in
	if in.Sans != nil {
		in, out := &in.Sans, &out.Sans
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.SignedWithPath != nil {
		in, out := &in.SignedWithPath, &out.SignedWithPath
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.PasswordPath != nil {
		in, out := &in.PasswordPath, &out.PasswordPath
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Node != nil {
		in, out := &in.Node, &out.Node
		*out = new(Node)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AliasConfig.
func (in *AliasConfig) DeepCopy() *AliasConfig {
	if in == nil {
		return nil
	}
	out := new(AliasConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AppConfig) DeepCopyInto(out *AppConfig) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AppConfig.
func (in *AppConfig) DeepCopy() *AppConfig {
	if in == nil {
		return nil
	}
	out := new(AppConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyConfig) DeepCopyInto(out *KeyConfig) {
	*out = *in
	if in.PrivateKeyPath != nil {
		in, out := &in.PrivateKeyPath, &out.PrivateKeyPath
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.StorePassPath != nil {
		in, out := &in.StorePassPath, &out.StorePassPath
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.KeyPassPath != nil {
		in, out := &in.KeyPassPath, &out.KeyPassPath
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AliasConfigs != nil {
		in, out := &in.AliasConfigs, &out.AliasConfigs
		*out = make([]*AliasConfig, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(AliasConfig)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.Node != nil {
		in, out := &in.Node, &out.Node
		*out = new(Node)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyConfig.
func (in *KeyConfig) DeepCopy() *KeyConfig {
	if in == nil {
		return nil
	}
	out := new(KeyConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Node) DeepCopyInto(out *Node) {
	*out = *in
	if in.Path != nil {
		in, out := &in.Path, &out.Path
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Parents != nil {
		in, out := &in.Parents, &out.Parents
		*out = make([]*Node, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(Node)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.Children != nil {
		in, out := &in.Children, &out.Children
		*out = make([]*Node, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(Node)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.SecretConfig != nil {
		in, out := &in.SecretConfig, &out.SecretConfig
		*out = new(SecretConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.KeyConfig != nil {
		in, out := &in.KeyConfig, &out.KeyConfig
		*out = new(KeyConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.AliasConfig != nil {
		in, out := &in.AliasConfig, &out.AliasConfig
		*out = new(AliasConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.Value != nil {
		in, out := &in.Value, &out.Value
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Node.
func (in *Node) DeepCopy() *Node {
	if in == nil {
		return nil
	}
	out := new(Node)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretAgentConfiguration) DeepCopyInto(out *SecretAgentConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretAgentConfiguration.
func (in *SecretAgentConfiguration) DeepCopy() *SecretAgentConfiguration {
	if in == nil {
		return nil
	}
	out := new(SecretAgentConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecretAgentConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretAgentConfigurationList) DeepCopyInto(out *SecretAgentConfigurationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SecretAgentConfiguration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretAgentConfigurationList.
func (in *SecretAgentConfigurationList) DeepCopy() *SecretAgentConfigurationList {
	if in == nil {
		return nil
	}
	out := new(SecretAgentConfigurationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecretAgentConfigurationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretAgentConfigurationSpec) DeepCopyInto(out *SecretAgentConfigurationSpec) {
	*out = *in
	out.AppConfig = in.AppConfig
	if in.Secrets != nil {
		in, out := &in.Secrets, &out.Secrets
		*out = make([]*SecretConfig, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(SecretConfig)
				(*in).DeepCopyInto(*out)
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretAgentConfigurationSpec.
func (in *SecretAgentConfigurationSpec) DeepCopy() *SecretAgentConfigurationSpec {
	if in == nil {
		return nil
	}
	out := new(SecretAgentConfigurationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretAgentConfigurationStatus) DeepCopyInto(out *SecretAgentConfigurationStatus) {
	*out = *in
	if in.ManagedK8sSecrets != nil {
		in, out := &in.ManagedK8sSecrets, &out.ManagedK8sSecrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ManagedAWSSecrets != nil {
		in, out := &in.ManagedAWSSecrets, &out.ManagedAWSSecrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ManagedGCPSecrets != nil {
		in, out := &in.ManagedGCPSecrets, &out.ManagedGCPSecrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretAgentConfigurationStatus.
func (in *SecretAgentConfigurationStatus) DeepCopy() *SecretAgentConfigurationStatus {
	if in == nil {
		return nil
	}
	out := new(SecretAgentConfigurationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretConfig) DeepCopyInto(out *SecretConfig) {
	*out = *in
	if in.Keys != nil {
		in, out := &in.Keys, &out.Keys
		*out = make([]*KeyConfig, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(KeyConfig)
				(*in).DeepCopyInto(*out)
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretConfig.
func (in *SecretConfig) DeepCopy() *SecretConfig {
	if in == nil {
		return nil
	}
	out := new(SecretConfig)
	in.DeepCopyInto(out)
	return out
}
