/*
Copyright 2025.

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
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NodeBalancerFirewallStatus struct {
	ID                    string      `json:"firewall-id,omitempty"`
	LastUpdate            metav1.Time `json:"last-update,omitempty"`
	NodeBalancerIDs       []int       `json:"nodebalancer-ids,omitempty"`
	NodeBalancerHostnames []string    `json:"nodebalancer-hostnames,omitempty"`
}

// NodeBalancerFirewallSpec defines the desired state of NodeBalancerFirewall
type NodeBalancerFirewallSpec struct {
	ImportID string      `json:"firewall-id,omitempty"`
	Ruleset  RulesetSpec `json:"ruleset,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NodeBalancerFirewall is the Schema for the nodebalancerfirewalls API.
type NodeBalancerFirewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeBalancerFirewallSpec   `json:"spec,omitempty"`
	Status NodeBalancerFirewallStatus `json:"status,omitempty"`
}

func (nf *NodeBalancerFirewall) Exists() bool {
	return nf.Status.ID != ""
}

func (nf *NodeBalancerFirewall) GetID() (int, error) {
	if nf.Exists() {
		return strconv.Atoi(nf.Status.ID)
	} else {
		return 0, fmt.Errorf("NodeBalancerFirewall ID does not exist")
	}
}

func (nf *NodeBalancerFirewall) GetStatusID() string {
	return nf.Status.ID
}

// +kubebuilder:object:root=true

// NodeBalancerFirewallList contains a list of NodeBalancerFirewall.
type NodeBalancerFirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeBalancerFirewall `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NodeBalancerFirewall{}, &NodeBalancerFirewallList{})
}
