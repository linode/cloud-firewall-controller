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
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The ruleset specs should be in sync with the structures defined in linodego:
// https://github.com/linode/linodego/blob/main/firewall_rules.go
//
// They are not directly imported in order to provide kubdebuilder with
// parameter limitations for the CRD. At runtime this allows the Cluster API
// to reject bad requests at the API rather than during reconciliation.
type AddressSpec struct {
	// +kubebuilder:validation:items:Pattern=`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2]?\d))?$`
	IPv4 *[]string `json:"ipv4,omitempty"`
	// +kubebuilder:validation:items:Pattern=`(?i)(?<ipv6>(?:[\da-f]{0,4}:){1,7}(?:(?<ipv4>(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?))|[\da-f]{0,4}))(\/(0?\d{1,2}|1([0-1]\d|2[0-8])))?`
	IPv6 *[]string `json:"ipv6,omitempty"`
}

type RuleSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ACCEPT;DROP
	Action string `json:"action"`
	// +kubebuilder:validation:Required
	Label string `json:"label"`
	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`
	// +kubebuilder:validation:Pattern=`^((6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})([,-]|$)){0,20}`
	Ports string `json:"ports,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=TCP;UDP;ICMP;IPENCAP
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:Required
	Addresses AddressSpec `json:"addresses"`
}

type RulesetSpec struct {
	Inbound []RuleSpec `json:"inbound,omitempty"`
	// +kubebuilder:validation:Enum=ACCEPT;DROP
	// +kubebuilder:default="DROP"
	InboundPolicy string     `json:"inbound_policy,omitempty"`
	Outbound      []RuleSpec `json:"outbound,omitempty"`
	// +kubebuilder:validation:Enum=ACCEPT;DROP
	// +kubebuilder:default="ACCEPT"
	OutboundPolicy string `json:"outbound_policy,omitempty"`
}

// CloudFirewallSpec defines the desired state of CloudFirewall
type CloudFirewallSpec struct {
	// When true (default), the controller will automatically apply the built-in default
	// ruleset in addition to any user-specified rules in .spec.ruleset.
	// Set to false to opt-out and manage all rules yourself.
	// +kubebuilder:default=true
	DefaultRules *bool       `json:"defaultRules,omitempty"`
	ImportID     string      `json:"firewall-id,omitempty"`
	Ruleset      RulesetSpec `json:"ruleset,omitempty"`
}

// CloudFirewallStatus defines the observed state of CloudFirewall
type CloudFirewallStatus struct {
	ID         string      `json:"firewall-id,omitempty"`
	Nodes      []int       `json:"nodes,omitempty"`
	LastUpdate metav1.Time `json:"last-update,omitempty"`
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

func (cf *CloudFirewall) Exists() bool {
	return cf.Status.ID != ""
}

func (cf *CloudFirewall) GetID() (int, error) {
	if cf.Exists() {
		return strconv.Atoi(cf.Status.ID)
	} else {
		return 0, fmt.Errorf("CloudFirewall ID does not exist")
	}
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
