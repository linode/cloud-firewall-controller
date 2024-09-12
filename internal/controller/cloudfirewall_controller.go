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
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
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

	alpha1v1 "bits.linode.com/hwagner/cloud-firewall-controller/api/alpha1v1"
	internal "bits.linode.com/hwagner/cloud-firewall-controller/internal/types"
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

var defaultRuleset = lgo.FirewallRuleSet{
	Inbound: []lgo.FirewallRule{
		{
			Action:      "ACCEPT",
			Description: "ICMP Traffic",
			Label:       "allow-all-icmp",
			Protocol:    "ICMP",
			Addresses: lgo.NetworkAddresses{
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
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Wireguard Traffic",
			Label:       "allow-lke-wireguard",
			Protocol:    "UDP",
			Ports:       "51820",
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster DNS",
			Label:       "allow-cluster-dns-tcp",
			Protocol:    "TCP",
			Ports:       "53",
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster DNS",
			Label:       "allow-cluster-dns-udp",
			Protocol:    "UDP",
			Ports:       "53",
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Nodeports",
			Label:       "allow-cluster-nodeports-tcp",
			Protocol:    "TCP",
			Ports:       "30000-32767",
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.255.0/24"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Nodeports",
			Label:       "allow-cluster-nodeports-udp",
			Protocol:    "UDP",
			Ports:       "30000-32767",
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.255.0/24"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "IPENCAP Private",
			Label:       "allow-cluster-nodeports-udp",
			Protocol:    "IPENCAP",
			Addresses: lgo.NetworkAddresses{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
	},
	InboundPolicy:  "DROP",
	Outbound:       []lgo.FirewallRule{},
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

	// This defer uses a deepcopy of the fetched CloudFirewall object to detect whether any Status updates
	// occured during the course of a reconciliation. If any changes have occured the Status will be updated
	// in etcd to be reflected into any subsequent reconciliations.
	defer func() {
		klog.V(1).Infof("[%s/%s] updating status current(%+v) update(%+v)", cf.Namespace, cf.Name, original.Status, cf.Status)
		if !reflect.DeepEqual(cf.Status, original.Status) {
			cf.Status.LastUpdate = metav1.Time{Time: time.Now()}
			if e := r.Status().Update(ctx, &cf); e != nil {
				err = fmt.Errorf("CloudFirewall status update failed: err=%s", e)
			}
		}
	}()

	// We require a CloudFirewall object in etcd to track state across reconciliations
	if err = r.Get(ctx, req.NamespacedName, &cf); err != nil {
		klog.Errorf("[%s/%s] failed to fetch CloudFirewall state - %s", req.Namespace, req.Name, err.Error())
		return
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

	if err = r.createLinodeClient(r.lApiOpts); err != nil {
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

	if !cf.Exists() {
		firewallLabel := fmt.Sprint("lke-", r.ClusterID)
		klog.Infof("[%s/%s] creating firewall label=(%s)", cf.Namespace, cf.Name, firewallLabel)
		if err = r.createFirewall(ctx, nodes, &cf); err != nil {
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
	klog.Infof("[%s/%s] getting firewall id=(%d)", cf.Namespace, cf.Name, firewallID)
	firewall, err = r.lcli.GetFirewall(ctx, firewallID)
	if err != nil {
		if FirewallIsNotFound(err) {
			klog.Infof("[%s/%s] firewall id=(%d) not found - recreating", cf.Namespace, cf.Name, firewallID)
			if err = r.createFirewall(ctx, nodes, &cf); err != nil {
				klog.Infof("[%s/%s] failed to create firewall - %s", cf.Namespace, cf.Name, err.Error())
			}
			// Either a firewall was created with the right node list or an error occured
			return
		} else {
			klog.Infof("[%s/%s] failed to get firewall id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
	}

	if !equalFirewallRuleSets(&firewall.Rules, &defaultRuleset) {
		klog.Infof("[%s/%s] changes found in firewall rules id=(%d)", cf.Namespace, cf.Name, firewallID)
		if _, err = r.lcli.UpdateFirewallRules(ctx, firewallID, defaultRuleset); err != nil {
			klog.Infof("[%s/%s] failed to update firewall rules id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
		klog.Infof("[%s/%s] updated firewall rules id=(%d)", cf.Namespace, cf.Name, firewallID)
	} else {
		klog.Infof("[%s/%s] firewall rules are up-to-date id=(%d)", cf.Namespace, cf.Name, firewallID)
	}

	if len(added) != 0 {
		if err = r.addNodes(ctx, added, firewallID, &cf); err != nil {
			klog.Infof("[%s/%s] failed to add nodes to firewall id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
		klog.Infof("[%s/%s] added nodes to firewall id=(%d) nodes=(%v)", cf.Namespace, cf.Name, firewallID, added)
	}

	if len(removed) != 0 {
		if err = r.removeNodes(ctx, removed, firewallID, &cf); err != nil {
			klog.Infof("[%s/%s] failed to remove nodes from firewall - %s", cf.Namespace, cf.Name, err.Error())
			return
		}
		klog.Infof("[%s/%s] removed nodes from firewall id=(%d) nodes=(%v)", cf.Namespace, cf.Name, firewallID, removed)
	}
	// On reconciliation success no need to reconcile unless triggered by Watch
	// Periodically we can reconcile to verify status
	return ctrl.Result{
		Requeue:      false,
		RequeueAfter: 10 * time.Hour,
	}, nil
}

func remove(s []int, i int) []int {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

func (r *CloudFirewallReconciler) removeNodes(ctx context.Context, nodes []int, firewallID int, cf *alpha1v1.CloudFirewall) (err error) {
	for _, node := range nodes {
		if err = r.lcli.DeleteFirewallDevice(ctx, firewallID, node); err != nil {
			err = fmt.Errorf("failed to remove device (%d) from firewall (%d) - %s", node, firewallID, err.Error())
		}
		// Remove the node from status list
		idx := slices.Index(cf.Status.Nodes, node)
		cf.Status.Nodes = remove(cf.Status.Nodes, idx)
	}
	return
}

func (r *CloudFirewallReconciler) addNodes(ctx context.Context, nodes []int, firewallID int, cf *alpha1v1.CloudFirewall) (err error) {
	for _, node := range nodes {
		opts := lgo.FirewallDeviceCreateOptions{
			ID:   node,
			Type: lgo.FirewallDeviceLinode,
		}
		if _, err = r.lcli.CreateFirewallDevice(ctx, firewallID, opts); err != nil {
			err = fmt.Errorf("failed to add device (%d) to firewall (%d)", node, firewallID)
			return
		}
		cf.Status.Nodes = append(cf.Status.Nodes, node)
	}
	return
}

func (r *CloudFirewallReconciler) createFirewall(ctx context.Context, nodes []int, cf *alpha1v1.CloudFirewall) (err error) {
	opts := lgo.FirewallCreateOptions{
		Label: fmt.Sprint("lke-", r.ClusterID),
		Rules: defaultRuleset,
		Devices: lgo.DevicesCreationOptions{
			Linodes: nodes,
		},
	}
	if firewall, err := r.lcli.CreateFirewall(ctx, opts); err != nil {
		err = fmt.Errorf("failed to create firewall - %s", err.Error())
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

// SetupWithManager sets up the controller with the Manager.
func (r *CloudFirewallReconciler) SetupWithManager(mgr ctrl.Manager, opts internal.LinodeApiOptions) error {
	r.lApiOpts = opts
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
							Name:      "default",
							Namespace: "kube-system",
						},
					}
					klog.Infof("[%s/%s] creating cluster default CloudFirewall object", cfObj.Namespace, cfObj.Name)
					if err := mgr.GetClient().Create(ctx, cfObj); err != nil {
						klog.Errorf("[%s/%s] failed to create default CloudFirewall", cfObj.Namespace, cfObj.Name)
					}
					// No need to schedule a reconcile here, the creation of the object will generate a reconciliation
					return reqs
				}

				for _, item := range cfList.Items {
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

func (r *CloudFirewallReconciler) createLinodeClient(opts internal.LinodeApiOptions) (err error) {
	creds := &corev1.Secret{}
	err = r.Get(context.TODO(), client.ObjectKey{
		Name:      opts.Credentials,
		Namespace: opts.CredentialsNs,
	},
		creds)
	if err != nil {
		return fmt.Errorf("failed to get API credentails: %s", err.Error())
	}

	apiKey := creds.Data["token"]
	if len(apiKey) == 0 {
		return fmt.Errorf("failed to parse Linode API token")
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: string(apiKey[:])})
	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}
	r.lcli = lgo.NewClient(oauth2Client)
	r.lcli.SetUserAgent(fmt.Sprintf("cloud-firewall-controller %s", lgo.DefaultUserAgent))
	r.lcli.SetDebug(opts.Debug)
	return
}
