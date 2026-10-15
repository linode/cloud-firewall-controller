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
//
// Importing replaces the firewall's whole ruleset, and the built-in defaults are
// written for standard LKE, so import mode requires an explicit decision about
// them, and defaultRules=false requires the rules the firewall needs. The
// controller enforces the same checks for CRDs that predate these rules.
// +kubebuilder:validation:XValidation:rule="!has(self.firewall__dash__id) || has(self.defaultRules)",message="defaultRules must be set explicitly when firewall-id is set"
// +kubebuilder:validation:XValidation:rule="!has(self.firewall__dash__id) || !has(self.defaultRules) || self.defaultRules || (has(self.ruleset) && has(self.ruleset.inbound) && size(self.ruleset.inbound) > 0)",message="with firewall-id set and defaultRules false, ruleset.inbound must list the rules the firewall needs"
type CloudFirewallSpec struct {
	// When true (the default when unset), the controller will automatically apply the
	// built-in default ruleset in addition to any user-specified rules in .spec.ruleset.
	// Set to false to opt-out and manage all rules yourself. Required when firewall-id
	// is set. There is deliberately no schema default: the controller treats unset as
	// true, and leaving it unset lets import mode tell "not decided" from "true".
	DefaultRules *bool `json:"defaultRules,omitempty"`
	// ID of an existing Cloud Firewall to manage instead of creating one. When set,
	// the controller only reconciles the firewall's rules (inbound, outbound and both
	// policies): it does not create the firewall, does not add or remove devices (the
	// firewall is expected to already be attached, e.g. via an LKE node pool's
	// firewall_id), and does not delete the firewall. A firewall attached to any
	// device outside this cluster is refused. Requires defaultRules to be set.
	// Removing this field releases the firewall untouched and the controller goes back
	// to creating its own.
	// +kubebuilder:validation:Pattern=`^[0-9]+$`
	ImportID string      `json:"firewall-id,omitempty"`
	Ruleset  RulesetSpec `json:"ruleset,omitempty"`
}

// CloudFirewallStatus defines the observed state of CloudFirewall
type CloudFirewallStatus struct {
	ID         string      `json:"firewall-id,omitempty"`
	Nodes      []int       `json:"nodes,omitempty"`
	LastUpdate metav1.Time `json:"last-update,omitempty"`
	// Conditions report import-mode state: Imported (adopted, or why not) and
	// NodesProtected (whether every node is attached to an imported firewall).
	// Informational only; the controller never derives ownership from them.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types and reasons set in .status.conditions.
const (
	ConditionImported       = "Imported"
	ConditionNodesProtected = "NodesProtected"
)

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

// ImportedAnnotation records the ID of the firewall the controller adopted from
// .spec.firewall-id. It is managed by the controller; do not edit it.
//
// It lives in metadata, not status, on purpose. With a CRD older than the
// controller (the CRD ships as a separate chart), the API server silently prunes
// status fields the CRD does not declare, and losing this marker would make an
// adopted firewall look controller-created: one the controller then attaches
// devices to and deletes. Metadata is never pruned.
const ImportedAnnotation = "networking.linode.com/imported-firewall-id"

// ImportRequested reports whether .spec.firewall-id asks the controller to adopt
// an existing firewall.
func (cf *CloudFirewall) ImportRequested() bool {
	return cf.Spec.ImportID != ""
}

// ImportedID returns the ID of the firewall the controller adopted, or "".
func (cf *CloudFirewall) ImportedID() string {
	return cf.Annotations[ImportedAnnotation]
}

// MarkedImported reports whether the firewall in .status is recorded as adopted
// (ImportedAnnotation) or named by .spec.firewall-id. Either marker excludes it
// from ownership, but neither proves ownership by its absence: the controller
// only treats a firewall as its own after checking the firewall itself (see the
// reconciler's owns), so losing a marker can never get a firewall deleted.
func (cf *CloudFirewall) MarkedImported() bool {
	id := cf.Status.ID
	return id != "" && (id == cf.ImportedID() || id == cf.Spec.ImportID)
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
