/*
Copyright 2024.

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

package alpha1v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CloudFirewallSpec defines the desired state of CloudFirewall
type CloudFirewallSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of CloudFirewall. Edit cloudfirewall_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// CloudFirewallStatus defines the observed state of CloudFirewall
type CloudFirewallStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CloudFirewall is the Schema for the cloudfirewalls API
type CloudFirewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudFirewallSpec   `json:"spec,omitempty"`
	Status CloudFirewallStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CloudFirewallList contains a list of CloudFirewall
type CloudFirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudFirewall `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CloudFirewall{}, &CloudFirewallList{})
}
