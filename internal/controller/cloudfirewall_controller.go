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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	alpha1v1 "github.com/linode/cloud-firewall-controller/api/alpha1v1"
	"github.com/linode/cloud-firewall-controller/internal/rules"
	internal "github.com/linode/cloud-firewall-controller/internal/types"
	lgo "github.com/linode/linodego"
)

// CloudFirewallReconciler reconciles a CloudFirewall object
type CloudFirewallReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	lcli      lgo.Client
	lApiOpts  internal.LinodeApiOptions
	ClusterID string
}

func (r *CloudFirewallReconciler) GetLClient() lgo.Client {
	return r.lcli
}

var defaultRuleset = alpha1v1.RulesetSpec{
	Inbound: []alpha1v1.RuleSpec{
		{
			Action:      "ACCEPT",
			Description: "ICMP Traffic",
			Label:       "allow-all-icmp",
			Protocol:    "ICMP",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"0.0.0.0/0"},
				IPv6: &[]string{"::/0"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Kubelet Health Checks",
			Label:       "allow-kubelet-health-checks",
			Protocol:    "TCP",
			Ports:       "10250,10256",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Wireguard Traffic",
			Label:       "allow-lke-wireguard",
			Protocol:    "UDP",
			Ports:       "51820",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster DNS",
			Label:       "allow-cluster-dns-tcp",
			Protocol:    "TCP",
			Ports:       "53",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster DNS",
			Label:       "allow-cluster-dns-udp",
			Protocol:    "UDP",
			Ports:       "53",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Calico BGP",
			Label:       "allow-calico-bgp",
			Protocol:    "TCP",
			Ports:       "179",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Nodeports",
			Label:       "allow-cluster-nodeports-tcp",
			Protocol:    "TCP",
			Ports:       "30000-32767",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.255.0/24"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Nodeports",
			Label:       "allow-cluster-nodeports-udp",
			Protocol:    "UDP",
			Ports:       "30000-32767",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.255.0/24"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "IPENCAP Private",
			Label:       "allow-cluster-ipencap",
			Protocol:    "IPENCAP",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
	},
	InboundPolicy:  "DROP",
	Outbound:       []alpha1v1.RuleSpec{},
	OutboundPolicy: "ACCEPT",
}

// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls/finalizers,verbs=update

// Additional required resource permissions
// watch nodes
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// watch and get Linode API token
//+kubebuilder:rbac:groups="",namespace=kube-system,resourceNames=linode,resources=secrets,verbs=get;list;watch

func (r *CloudFirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	_ = log.FromContext(ctx)
	var original alpha1v1.CloudFirewall
	var cf alpha1v1.CloudFirewall
	var deleted bool

	// This defer uses a deepcopy of the fetched CloudFirewall object to detect whether any Status updates
	// occured during the course of a reconciliation. If any changes have occured the Status will be updated
	// in etcd to be reflected into any subsequent reconciliations.
	defer func() {
		if deleted {
			// do nothing the object is being removed
		} else if !reflect.DeepEqual(cf.ObjectMeta, original.ObjectMeta) {
			// If the metadata has changed we need to update the whole object
			klog.V(1).Infof("[%s/%s] metadata change detected current(%+v) update(%+v)", cf.Namespace, cf.Name, original.ObjectMeta, cf.ObjectMeta)
			cf.Status.LastUpdate = metav1.Time{Time: time.Now()}
			if e := r.Update(ctx, &cf); e != nil {
				err = fmt.Errorf("CloudFirewall update failed: err=%s", e)
			}
		} else if !reflect.DeepEqual(cf.Status, original.Status) {
			// Otherwise we can just update the internal status
			klog.V(1).Infof("[%s/%s] status change detected current(%+v) update(%+v)", cf.Namespace, cf.Name, original.Status, cf.Status)
			cf.Status.LastUpdate = metav1.Time{Time: time.Now()}
			if e := r.Status().Update(ctx, &cf); e != nil {
				err = fmt.Errorf("CloudFirewall status update failed: err=%s", e)
			}
		}
	}()

	// We require a CloudFirewall object in etcd to track state across reconciliations
	if err = r.Get(ctx, req.NamespacedName, &cf); err != nil {
		klog.Errorf("[%s/%s] failed to fetch CloudFirewall state - %s", req.Namespace, req.Name, err.Error())
		// If the object no longer exists we don't want to come back
		return ctrl.Result{}, nil
	}
	// Save current state to compare in the defer function
	original = *cf.DeepCopy()

	// Fetch clusterID from cluster API. Occurs once per controller instantiation
	if r.ClusterID == "" {
		if r.ClusterID, err = getClusterID(ctx, r.Client); err != nil {
			klog.Errorf("[%s/%s] failed to get clusterID - %s", req.Namespace, req.Name, err.Error())
			return
		}
	}
	klog.Infof("[%s/%s] using clusterID (%s)", cf.Namespace, cf.Name, r.ClusterID)

	if err = createLinodeClient(r, r.lApiOpts); err != nil {
		// can't proceed without valid Linode Creds, retry on exponential backoff
		klog.Errorf("[%s/%s] failed to get API credentials - %s", r.lApiOpts.Credentials, r.lApiOpts.CredentialsNs, err.Error())
		return
	}
	klog.Infof("[%s/%s] using credentials (%s/%s)", cf.Namespace, cf.Name, r.lApiOpts.Credentials, r.lApiOpts.CredentialsNs)

	nodes, added, removed, err := nodeListChanges(ctx, cf, r.Client)
	if err != nil {
		klog.Errorf("[%s/%s] failed to check node list - %s", cf.Namespace, cf.Name, err.Error())
		return
	}
	klog.Infof("[%s/%s] current nodes: %v", cf.Namespace, cf.Name, nodes)
	klog.Infof("[%s/%s] added nodes: %v", cf.Namespace, cf.Name, added)
	klog.Infof("[%s/%s] removed nodes: %v", cf.Namespace, cf.Name, removed)

	// Build the effective ruleset based on defaultRules flag and user-specified rules
	effective := effectiveRulesetSpec(cf.Spec)
	newRuleset, err := toLinodeFirewallRuleset(effective)
	if err != nil {
		klog.Infof("[%s/%s] failed to convert FirewallRuleset - %s", cf.Namespace, cf.Name, err.Error())
	}

	if !cf.Exists() {
		firewallLabel := fmt.Sprint("lke-", r.ClusterID)
		klog.Infof("[%s/%s] creating firewall label=(%s)", cf.Namespace, cf.Name, firewallLabel)
		if err = r.createFirewall(ctx, nodes, &cf, newRuleset); err != nil {
			klog.Infof("[%s/%s] failed to create firewall - %s", cf.Namespace, cf.Name, err.Error())
		}
		return
	}

	// Rate limit how often we hit the Linode API
	// The incremental steps taken to add nodes to the cluster results in triggering several
	// reconciliations per node, which can hammer to API for a short period of time with Get calls.
	// In order to reduce that and give the scheduler a chance to flatten the reconcile calls this
	// introduces a small wait period.
	minimumUpdateDuration := time.Second * 10
	if time.Since(cf.Status.LastUpdate.Time) < time.Second*10 {
		klog.Infof("[%s/%s] update duration not met - requeuing %v", cf.Namespace, cf.Name, minimumUpdateDuration)
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
			Requeue:      true,
		}, nil
	}

	var firewall *lgo.Firewall
	firewallID, err := cf.GetID()
	if err != nil {
		klog.Errorf("[%s/%s] failed to get firewallID - %s", cf.Namespace, cf.Name, err.Error())
		return
	}

	if err = r.checkOwnership(ctx, &cf); err != nil {
		klog.Errorf("[%s/%s] failed finalizer check - %s", cf.Namespace, cf.Name, err.Error())
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
			Requeue:      true,
		}, err
	}

	if deleted, err = r.checkFinalizer(ctx, &cf); err != nil {
		klog.Errorf("[%s/%s] failed finalizer check - %s", cf.Namespace, cf.Name, err.Error())
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
			Requeue:      true,
		}, err
	} else if deleted {
		return
	}

	klog.Infof("[%s/%s] getting firewall id=(%d)", cf.Namespace, cf.Name, firewallID)
	firewall, err = r.lcli.GetFirewall(ctx, firewallID)
	if err != nil {
		if FirewallIsNotFound(err) {
			klog.Infof("[%s/%s] firewall id=(%d) not found - recreating", cf.Namespace, cf.Name, firewallID)
			if err = r.createFirewall(ctx, nodes, &cf, newRuleset); err != nil {
				klog.Infof("[%s/%s] failed to create firewall - %s", cf.Namespace, cf.Name, err.Error())
			}
			// Either a firewall was created with the right node list or an error occured
			return
		} else {
			klog.Infof("[%s/%s] failed to get firewall id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
	}

	if !equalFirewallRuleSets(&firewall.Rules, &newRuleset) {
		klog.Infof("[%s/%s] changes found in firewall rules id=(%d)", cf.Namespace, cf.Name, firewallID)
		if _, err = r.lcli.UpdateFirewallRules(ctx, firewallID, newRuleset); err != nil {
			klog.Infof("[%s/%s] failed to update firewall rules id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
		klog.Infof("[%s/%s] updated firewall rules id=(%d)", cf.Namespace, cf.Name, firewallID)
	} else {
		klog.Infof("[%s/%s] firewall rules are up-to-date id=(%d)", cf.Namespace, cf.Name, firewallID)
	}

	if len(added) != 0 {
		if err = r.addDevices(ctx, added, firewallID, &cf); err != nil {
			klog.Infof("[%s/%s] failed to add nodes to firewall id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
		klog.Infof("[%s/%s] added nodes to firewall id=(%d) nodes=(%v)", cf.Namespace, cf.Name, firewallID, added)
	}

	if len(removed) != 0 {
		if err = r.removeDevices(ctx, removed, firewallID, &cf); err != nil {
			klog.Infof("[%s/%s] failed to remove nodes from firewall - %s", cf.Namespace, cf.Name, err.Error())
			return
		}
		klog.Infof("[%s/%s] removed nodes from firewall id=(%d) nodes=(%v)", cf.Namespace, cf.Name, firewallID, removed)
	}
	// On reconciliation success no need to reconcile unless triggered by Watch
	// Periodically we can reconcile to verify status
	klog.Infof("[%s/%s] reconcile complete firewall id=(%d)", cf.Namespace, cf.Name, firewallID)
	return ctrl.Result{
		Requeue:      false,
		RequeueAfter: 10 * time.Hour,
	}, nil
}

func (r *CloudFirewallReconciler) checkOwnership(ctx context.Context, cf *alpha1v1.CloudFirewall) error {
	return checkOwnership(ctx, r, cf, r.Scheme)
}

func (r *CloudFirewallReconciler) checkFinalizer(ctx context.Context, cf *alpha1v1.CloudFirewall) (bool, error) {
	return checkFinalizer(ctx, r, cf, "cloudfirewalls")
}

func (r *CloudFirewallReconciler) deleteExternalResources(ctx context.Context, cf FirewallObject) error {
	return deleteExternalResources(ctx, r, cf)
}

func (r *CloudFirewallReconciler) removeDevices(ctx context.Context, nodes []int, firewallID int, nf *alpha1v1.CloudFirewall) error {
	return removeDevices(ctx, r, nodes, firewallID, &nf.Status.Nodes)
}

func (r *CloudFirewallReconciler) addDevices(ctx context.Context, nodes []int, firewallID int, nf *alpha1v1.CloudFirewall) error {
	return addDevices(ctx, r, nodes, firewallID, lgo.FirewallDeviceLinode, &nf.Status.Nodes)
}

func (r *CloudFirewallReconciler) createFirewall(ctx context.Context, nodes []int, cf *alpha1v1.CloudFirewall, rs lgo.FirewallRuleSet) (err error) {
	opts := lgo.FirewallCreateOptions{
		Label: fmt.Sprint("lke-", r.ClusterID),
		Rules: rs,
		Devices: lgo.DevicesCreationOptions{
			Linodes: nodes,
		},
	}
	if firewall, err := r.lcli.CreateFirewall(ctx, opts); err != nil {
		err = fmt.Errorf("failed to create firewall - %s", err.Error())
		return err
	} else {
		cf.Status.ID = strconv.Itoa(firewall.ID)
		cf.Status.Nodes = nodes
	}
	return
}

func nodeListChanges(ctx context.Context, cf alpha1v1.CloudFirewall, cli client.Client) (nodes []int, added []int, removed []int, err error) {
	// Get list of cluster nodes
	nodeList := &corev1.NodeList{}
	if err = cli.List(ctx, nodeList); err != nil {
		err = fmt.Errorf("unable to get node list - %s", err.Error())
		return
	}

	// Build list of NodeIDs
	// This could be optimized, but for simplicity it is what it is
	for _, node := range nodeList.Items {
		var nodeID int
		if node.Spec.ProviderID == "" {
			// On node deletion an event will be triggered and the node object will exists past
			// the call to delete the underlying linode. The ProviderID will be empty as soon
			// as the Linode is deleted.
			continue
		}
		klog.V(3).Infof("[%s/%s] found provider(%s)", cf.Namespace, cf.Name, node.Spec.ProviderID)
		nodeIDstr := trimProviderID(node.Spec.ProviderID)
		klog.V(3).Infof("[%s/%s] trimmed nodeID(%s)", cf.Namespace, cf.Name, nodeIDstr)
		nodeID, err = strconv.Atoi(trimProviderID(node.Spec.ProviderID))
		if err != nil {
			err = fmt.Errorf("failed to parse nodeID (%v)", node.Spec.ProviderID)
			return
		}
		klog.V(2).Infof("[%s/%s] found node (%d)", cf.Namespace, cf.Name, nodeID)
		nodes = append(nodes, nodeID)
	}

	for _, node := range nodes {
		if !slices.Contains(cf.Status.Nodes, node) {
			added = append(added, node)
		}
	}

	for _, node := range cf.Status.Nodes {
		if !slices.Contains(nodes, node) {
			removed = append(removed, node)
		}
	}
	return
}

func trimProviderID(providerID string) (nodeID string) {
	nodeID, _ = strings.CutPrefix(providerID, "linode://")
	return
}

func equalFirewallRuleSets(a *lgo.FirewallRuleSet, b *lgo.FirewallRuleSet) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.InboundPolicy == b.InboundPolicy &&
		a.OutboundPolicy == b.OutboundPolicy &&
		equalFirewallRules(a.Inbound, b.Inbound) &&
		equalFirewallRules(a.Outbound, b.Outbound)
}

func equalFirewallRules(a []lgo.FirewallRule, b []lgo.FirewallRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalFirewallRule(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalFirewallRule(a lgo.FirewallRule, b lgo.FirewallRule) bool {
	return a.Action == b.Action &&
		a.Label == b.Label &&
		a.Description == b.Description &&
		a.Ports == b.Ports &&
		a.Protocol == b.Protocol &&
		equalCIDRs(a.Addresses.IPv4, b.Addresses.IPv4, 4) &&
		equalCIDRs(a.Addresses.IPv6, b.Addresses.IPv6, 6)
}

func cidrString(input string, ipVer int) string {
	ip, mask, err := net.ParseCIDR(input)
	if err != nil {
		ip = net.ParseIP(input)
		if ip == nil {
			return ""
		}
		if ipVer == 4 {
			return ip.String() + "/32"
		}
		if ipVer == 6 {
			return ip.String() + "/128"
		}
	}
	return mask.String()
}

func equalCIDRs(a *[]string, b *[]string, ipVer int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil || (len(*a) != len(*b)) {
		return false
	}
	aCopy := []string{}
	bCopy := []string{}
	for i := range *a {
		aCopy = append(aCopy, (*a)[i])
		bCopy = append(bCopy, (*b)[i])
	}
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if cidrString(aCopy[i], ipVer) != cidrString(bCopy[i], ipVer) {
			return false
		}
	}
	return true
}

func getClusterID(ctx context.Context, cli client.Client) (string, error) {
	clusterID := ""
	nodes := corev1.NodeList{}
	if err := cli.List(ctx, &nodes); err != nil {
		return "", fmt.Errorf("unable to get clusterID, no nodes found")
	}
	if len(nodes.Items) > 0 {
		found := false
		nodeName := nodes.Items[0].GetName()
		clusterLabel, _, found := strings.Cut(nodeName, "-")
		if found {
			klog.Infof("found clusterLabel(%s)", clusterLabel)
			clusterID, found = strings.CutPrefix(clusterLabel, "lke")
		} else {
			return "", fmt.Errorf("unable to extract clusterLabel from node label (%s)", nodeName)
		}
		if !found {
			return "", fmt.Errorf("unable to trim 'lke' from clusterLabel (%s)", clusterID)
		}
		klog.Infof("found clusterID(%s)", clusterID)
	}
	return clusterID, nil
}

func FirewallIsNotFound(err error) bool {
	originalErr, ok := err.(*lgo.Error)
	klog.Infof("linode client error (%+v)", originalErr.Code)
	if ok && originalErr.Code == 404 {
		return true
	}
	return false
}

func toLinodeFirewallRuleset(ruleset alpha1v1.RulesetSpec) (lgo.FirewallRuleSet, error) {
	var lrs lgo.FirewallRuleSet
	var err error

	rulesetStr, err := json.Marshal(ruleset)
	if err != nil {
		return lgo.FirewallRuleSet{}, fmt.Errorf("unable to marshal CloudFirewall ruleset - %s", err.Error())
	}

	err = json.Unmarshal(rulesetStr, &lrs)
	if err != nil {
		return lgo.FirewallRuleSet{}, fmt.Errorf("unable to unmarshal CloudFirewall ruleset - %s", err.Error())
	}

	return lrs, nil
}

// defaultRulesEnabled returns true when cf.Spec.DefaultRules == nil or true
func defaultRulesEnabled(spec alpha1v1.CloudFirewallSpec) bool {
	if spec.DefaultRules == nil {
		return true
	}
	return *spec.DefaultRules
}

// effectiveRulesetSpec merges the default ruleset with user-provided rules
// when default rules are enabled. User rules are appended after defaults to
// ensure consistent evaluation order. Policies default to DROP/ACCEPT if empty.
func effectiveRulesetSpec(spec alpha1v1.CloudFirewallSpec) alpha1v1.RulesetSpec {
	rs := alpha1v1.RulesetSpec{}

	// Start with policies from spec or defaults
	if spec.Ruleset.InboundPolicy != "" {
		rs.InboundPolicy = spec.Ruleset.InboundPolicy
	} else {
		rs.InboundPolicy = "DROP"
	}
	if spec.Ruleset.OutboundPolicy != "" {
		rs.OutboundPolicy = spec.Ruleset.OutboundPolicy
	} else {
		rs.OutboundPolicy = "ACCEPT"
	}

	// Merge defaults when enabled (skip any that are already in user rules)
	if defaultRulesEnabled(spec) {
		def := rules.DefaultRuleset()
		// Append default inbound rules first, but skip duplicates
		for _, defaultRule := range def.Inbound {
			if !containsRule(spec.Ruleset.Inbound, defaultRule) {
				rs.Inbound = append(rs.Inbound, defaultRule)
			}
		}
	}
	// Append user inbound rules
	if len(spec.Ruleset.Inbound) > 0 {
		rs.Inbound = append(rs.Inbound, spec.Ruleset.Inbound...)
	}
	// Outbound rules: defaults currently empty; still allow user outbound
	if defaultRulesEnabled(spec) {
		def := rules.DefaultRuleset()
		if len(def.Outbound) > 0 {
			for _, defaultRule := range def.Outbound {
				if !containsRule(spec.Ruleset.Outbound, defaultRule) {
					rs.Outbound = append(rs.Outbound, defaultRule)
				}
			}
		}
	}
	if len(spec.Ruleset.Outbound) > 0 {
		rs.Outbound = append(rs.Outbound, spec.Ruleset.Outbound...)
	}

	return rs
}

// containsRule checks if the given slice already contains an equal rule
func containsRule(list []alpha1v1.RuleSpec, target alpha1v1.RuleSpec) bool {
	for _, r := range list {
		if ruleEqual(r, target) {
			return true
		}
	}
	return false
}

// ruleEqual compares two rules for equality
func ruleEqual(a, b alpha1v1.RuleSpec) bool {
	if a.Action != b.Action || a.Label != b.Label || a.Description != b.Description || a.Ports != b.Ports || a.Protocol != b.Protocol {
		return false
	}
	return addressEqual(a.Addresses, b.Addresses)
}

// addressEqual compares two address specs for equality
func addressEqual(a, b alpha1v1.AddressSpec) bool {
	if !stringSlicesEqual(a.IPv4, b.IPv4) {
		return false
	}
	if !stringSlicesEqual(a.IPv6, b.IPv6) {
		return false
	}
	return true
}

// stringSlicesEqual compares two string slice pointers for equality
func stringSlicesEqual(a, b *[]string) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil) != (b == nil) {
		return false
	}
	if len(*a) != len(*b) {
		return false
	}
	for i := range *a {
		if (*a)[i] != (*b)[i] {
			return false
		}
	}
	return true
}

// SetupWithManager sets up the controller with the Manager.
func (r *CloudFirewallReconciler) SetupWithManager(mgr ctrl.Manager, opts internal.LinodeApiOptions) error {
	r.lApiOpts = opts

	latestRevision := rules.LatestRevision()
	klog.Infof("latest ruleset revision: %s", latestRevision)
	previousRevisions := rules.PreviousRevisions()
	for _, rev := range previousRevisions {
		klog.Infof("previous ruleset revision: %s", rev)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&alpha1v1.CloudFirewall{}).

		// Watch for cluster worker node changes to trigger reconciliation
		// to update firewalls appropriately. These events do not tell us explicitly
		// what has changed and may be triggered more often than expected. This is due
		// to the Node controller updating status fields that are not relevent to this controller.
		// We must watch all status changes due to the IP set of a Node being stored
		// in the Status object, which we cannot filter until the reconciliation phase.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, node client.Object) []reconcile.Request {
				klog.V(2).Infof("[%s] node updated: %s", node.GetNamespace(), node.GetName())
				cfList := &alpha1v1.CloudFirewallList{}
				if err := mgr.GetClient().List(ctx, cfList); err != nil {
					klog.Errorf("failed to list CloudFirewalls - %s", err.Error())
					return nil
				}
				reqs := make([]reconcile.Request, 0, len(cfList.Items))
				// If for any reason no default CloudFirewall object exists attempt to create it
				if len(cfList.Items) == 0 {
					klog.Infof("no CloudFirewalls found")
					cfObj := &alpha1v1.CloudFirewall{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "primary",
							Namespace: "kube-system",
						},
						Spec: alpha1v1.CloudFirewallSpec{},
					}
					klog.Infof("[%s/%s] creating cluster default CloudFirewall object", cfObj.Namespace, cfObj.Name)
					if err := mgr.GetClient().Create(ctx, cfObj); err != nil {
						klog.Errorf("[%s/%s] failed to create default CloudFirewall - %s", cfObj.Namespace, cfObj.Name, err.Error())
					}
					// No need to schedule a reconcile here, the creation of the object will generate a reconciliation
					return reqs
				}

				for _, item := range cfList.Items {

					rulesHash := rules.Sha256Hash(item.Spec.Ruleset)
					klog.V(2).Infof("[%s/%s] CloudFirewall ruleset hash: %s", item.Namespace, item.Name, rulesHash)

					// Compute what the effective rules would be if we applied defaults plus user rules
					effective := effectiveRulesetSpec(item.Spec)
					effectiveHash := rules.Sha256Hash(effective)
					if effectiveHash == latestRevision {
						klog.Infof("[%s/%s] CloudFirewall object is up-to-date with latest revision %s", item.Namespace, item.Name, latestRevision)
					} else {
						klog.Infof("[%s/%s] CloudFirewall object effective ruleset does not match latest revision %s != %s", item.Namespace, item.Name, effectiveHash, latestRevision)

						if slices.Contains(previousRevisions, rulesHash) || slices.Contains(previousRevisions, effectiveHash) {
							klog.Infof("[%s/%s] CloudFirewall object ruleset matches a previous revision %s", item.Namespace, item.Name, rulesHash)
							// Migrate to new model: enable defaultRules and remove explicit default rules from spec
							trueVal := true
							item.Spec.DefaultRules = &trueVal
							item.Spec.Ruleset = alpha1v1.RulesetSpec{}
							item.Status.LastUpdate = metav1.Time{Time: time.Now()}
							if err := mgr.GetClient().Update(ctx, &item); err != nil {
								klog.Errorf("[%s/%s] failed to update default CloudFirewall object - %s", item.Namespace, item.Name, err.Error())
							}
							// No need to schedule a reconcile here, the update of the object will generate a reconciliation
							// and we can continue to the next item.
							klog.Infof("[%s/%s] CloudFirewall object migrated to defaultRules model. Skipping scheduling", item.Namespace, item.Name)
							continue

						} else {
							klog.Warningf("[%s/%s] CloudFirewall object ruleset does not match latest or previous revisions. Cannot upgrade custom ruleset %s != %s or %v", item.Namespace, item.Name, effectiveHash, latestRevision, previousRevisions)
						}
					}

					klog.Infof("[%s] scheduling CloudFirewall reconciliation: %s", item.Namespace, item.Name)
					reqs = append(reqs, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Namespace: item.GetNamespace(),
							Name:      item.GetName(),
						},
					})
				}
				return reqs
			}),
			builder.WithPredicates(
				predicate.Or(
					predicate.GenerationChangedPredicate{},
					predicate.AnnotationChangedPredicate{},
				))).Complete(r)
}

// func (r *CloudFirewallReconciler) createLinodeClient(opts internal.LinodeApiOptions) (err error) {
// 	creds := &corev1.Secret{}
// 	err = r.Get(context.TODO(), client.ObjectKey{
// 		Name:      opts.Credentials,
// 		Namespace: opts.CredentialsNs,
// 	},
// 		creds)
// 	if err != nil {
// 		return fmt.Errorf("failed to get API credentails: %s", err.Error())
// 	}

// 	apiKey := creds.Data["token"]
// 	if len(apiKey) == 0 {
// 		return fmt.Errorf("failed to parse Linode API token")
// 	}
// 	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: string(apiKey[:])})
// 	oauth2Client := &http.Client{
// 		Transport: &oauth2.Transport{
// 			Source: tokenSource,
// 		},
// 	}
// 	r.lcli = lgo.NewClient(oauth2Client)
// 	r.lcli.SetUserAgent(fmt.Sprintf("cloud-firewall-controller %s", lgo.DefaultUserAgent))
// 	r.lcli.SetDebug(opts.Debug)
// 	return
// }
