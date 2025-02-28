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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"time"

	lgo "github.com/linode/linodego"
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
)

// NodeBalancerFirewallReconciler reconciles a NodeBalancerFirewall object
type NodeBalancerFirewallReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	lcli      lgo.Client
	lApiOpts  internal.LinodeApiOptions
	ClusterID string
}

func (r *NodeBalancerFirewallReconciler) GetLClient() lgo.Client {
	return r.lcli
}

// +kubebuilder:rbac:groups=networking.linode.com,resources=nodebalancerfirewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.linode.com,resources=nodebalancerfirewalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.linode.com,resources=nodebalancerfirewalls/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",namespace=kube-system,resourceNames=linode,resources=secrets,verbs=get;list;watch

func (r *NodeBalancerFirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	_ = log.FromContext(ctx)
	var original alpha1v1.NodeBalancerFirewall
	var nf alpha1v1.NodeBalancerFirewall
	var deleted bool

	// This defer uses a deepcopy of the fetched NodeBalancerFirewall object to detect whether any Status updates
	// occured during the course of a reconciliation. If any changes have occured the Status will be updated
	// in etcd to be reflected into any subsequent reconciliations.
	defer func() {
		if deleted {
			// do nothing the object is being removed
		} else if !reflect.DeepEqual(nf.ObjectMeta, original.ObjectMeta) {
			// If the metadata has changed we need to update the whole object
			klog.V(1).Infof("[%s/%s] metadata change detected current(%+v) update(%+v)", nf.Namespace, nf.Name, original.ObjectMeta, nf.ObjectMeta)
			nf.Status.LastUpdate = metav1.Time{Time: time.Now()}
			if e := r.Update(ctx, &nf); e != nil {
				err = fmt.Errorf("NodeBalancerFirewall update failed: err=%s", e)
			}
		} else if !reflect.DeepEqual(nf.Status, original.Status) {
			// Otherwise we can just update the internal status
			klog.V(1).Infof("[%s/%s] status change detected current(%+v) update(%+v)", nf.Namespace, nf.Name, original.Status, nf.Status)
			nf.Status.LastUpdate = metav1.Time{Time: time.Now()}
			if e := r.Status().Update(ctx, &nf); e != nil {
				err = fmt.Errorf("NodeBalancerFirewall status update failed: err=%s", e)
			}
		}
	}()

	// We require a NodeBalancerFirewall object in etcd to track state across reconciliations
	if err = r.Get(ctx, req.NamespacedName, &nf); err != nil {
		klog.Errorf("[%s/%s] failed to fetch NodeBalancerFirewall state - %s", req.Namespace, req.Name, err.Error())
		// If the object no longer exists we don't want to come back
		return ctrl.Result{}, nil
	}
	// Save current state to compare in the defer function
	original = *nf.DeepCopy()

	// Fetch clusterID from cluster API. Occurs once per controller instantiation
	if r.ClusterID == "" {
		if r.ClusterID, err = getClusterID(ctx, r.Client); err != nil {
			klog.Errorf("[%s/%s] failed to get clusterID - %s", req.Namespace, req.Name, err.Error())
			return
		}
	}
	klog.Infof("[%s/%s] using clusterID (%s)", nf.Namespace, nf.Name, r.ClusterID)

	if err = r.createLinodeClient(r.lApiOpts); err != nil {
		// can't proceed without valid Linode Creds, retry on exponential backoff
		klog.Errorf("[%s/%s] failed to get API credentials - %s", r.lApiOpts.Credentials, r.lApiOpts.CredentialsNs, err.Error())
		return
	}
	klog.Infof("[%s/%s] using credentials (%s/%s)", nf.Namespace, nf.Name, r.lApiOpts.Credentials, r.lApiOpts.CredentialsNs)

	nodes, added, removed, err := nodeBalancerListChanges(ctx, nf, r.Client)
	if err != nil {
		klog.Errorf("[%s/%s] failed to check node list - %s", nf.Namespace, nf.Name, err.Error())
		return
	}
	klog.Infof("[%s/%s] current nodebalancers: %v", nf.Namespace, nf.Name, nodes)
	klog.Infof("[%s/%s] added nodebalancers: %v", nf.Namespace, nf.Name, added)
	klog.Infof("[%s/%s] removed nodebalancers: %v", nf.Namespace, nf.Name, removed)

	newRuleset, err := toLinodeFirewallRuleset(nf.Spec.Ruleset)
	if err != nil {
		klog.Infof("[%s/%s] failed to convert FirewallRuleset - %s", nf.Namespace, nf.Name, err.Error())
	}

	if !nf.Exists() {
		var ids []int
		ids, err = getNodeBalancerIDs(ctx, r, nodes)
		if err != nil {
			klog.Infof("[%s/%s] failed to get NodeBalancer IDs - %s", nf.Namespace, nf.Name, err.Error())
			return
		}

		firewallLabel := fmt.Sprint("lke-nb-", r.ClusterID)
		klog.Infof("[%s/%s] creating firewall label=(%s)", nf.Namespace, nf.Name, firewallLabel)
		if err = r.createFirewall(ctx, ids, &nf, newRuleset); err != nil {
			klog.Infof("[%s/%s] failed to create firewall - %s", nf.Namespace, nf.Name, err.Error())
		} else {
			nf.Status.NodeBalancerHostnames = nodes
		}

		return
	}

	// Rate limit how often we hit the Linode API
	// The incremental steps taken to add nodes to the cluster results in triggering several
	// reconciliations per node, which can hammer to API for a short period of time with Get calls.
	// In order to reduce that and give the scheduler a chance to flatten the reconcile calls this
	// introduces a small wait period.
	minimumUpdateDuration := time.Second * 10
	if time.Since(nf.Status.LastUpdate.Time) < time.Second*10 {
		klog.Infof("[%s/%s] update duration not met - requeuing %v", nf.Namespace, nf.Name, minimumUpdateDuration)
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
			Requeue:      true,
		}, nil
	}

	var firewall *lgo.Firewall
	firewallID, err := nf.GetID()
	if err != nil {
		klog.Errorf("[%s/%s] failed to get firewallID - %s", nf.Namespace, nf.Name, err.Error())
		return
	}

	if err = r.checkOwnership(ctx, &nf); err != nil {
		klog.Errorf("[%s/%s] failed finalizer check - %s", nf.Namespace, nf.Name, err.Error())
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
			Requeue:      true,
		}, err
	}

	if deleted, err = r.checkFinalizer(ctx, &nf); err != nil {
		klog.Errorf("[%s/%s] failed finalizer check - %s", nf.Namespace, nf.Name, err.Error())
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
			Requeue:      true,
		}, err
	} else if deleted {
		return
	}

	klog.Infof("[%s/%s] getting firewall id=(%d)", nf.Namespace, nf.Name, firewallID)
	firewall, err = r.lcli.GetFirewall(ctx, firewallID)
	if err != nil {
		if FirewallIsNotFound(err) {
			var ids []int
			ids, err = getNodeBalancerIDs(ctx, r, nodes)
			if err != nil {
				klog.Infof("[%s/%s] failed to get NodeBalancer IDs - %s", nf.Namespace, nf.Name, err.Error())
				return
			}

			klog.Infof("[%s/%s] firewall id=(%d) not found - recreating", nf.Namespace, nf.Name, firewallID)
			if err = r.createFirewall(ctx, ids, &nf, newRuleset); err != nil {
				klog.Infof("[%s/%s] failed to create firewall - %s", nf.Namespace, nf.Name, err.Error())
			} else {
				nf.Status.NodeBalancerHostnames = nodes
			}
			// Either a firewall was created with the right node list or an error occured
			return
		} else {
			klog.Infof("[%s/%s] failed to get firewall id=(%d) - %s", nf.Namespace, nf.Name, firewallID, err.Error())
			return
		}
	}

	if !equalFirewallRuleSets(&firewall.Rules, &newRuleset) {
		klog.Infof("[%s/%s] changes found in firewall rules id=(%d)", nf.Namespace, nf.Name, firewallID)
		if _, err = r.lcli.UpdateFirewallRules(ctx, firewallID, newRuleset); err != nil {
			klog.Infof("[%s/%s] failed to update firewall rules id=(%d) - %s", nf.Namespace, nf.Name, firewallID, err.Error())
			return
		}
		klog.Infof("[%s/%s] updated firewall rules id=(%d)", nf.Namespace, nf.Name, firewallID)
	} else {
		klog.Infof("[%s/%s] firewall rules are up-to-date id=(%d)", nf.Namespace, nf.Name, firewallID)
	}

	if len(added) != 0 || len(removed) != 0 {
		var nbMap map[string]int
		nbMap, err = r.getNodeBalancerIDMap(ctx)
		if err != nil {
			klog.Infof("failed to fetch NodeBalancer ID mapping: %s", err.Error())
		}

		if len(added) != 0 {
			// Convert hostnames to IDs
			ids := make([]int, 0, len(added))
			for _, hostname := range added {
				if id, exists := nbMap[hostname]; exists {
					ids = append(ids, id)
				}
			}
			if err = r.addDevices(ctx, ids, firewallID, &nf); err != nil {
				klog.Infof("[%s/%s] failed to add nodebalancers to firewall id=(%d) - %s", nf.Namespace, nf.Name, firewallID, err.Error())
				return
			} else {
				nf.Status.NodeBalancerHostnames = append(nf.Status.NodeBalancerHostnames, added...)
			}
			klog.Infof("[%s/%s] added nodebalancers to firewall id=(%d) nodebalancers=(%v)", nf.Namespace, nf.Name, firewallID, ids)
		}

		if len(removed) != 0 {
			ids := make([]int, 0, len(removed))
			for _, hostname := range removed {
				if id, exists := nbMap[hostname]; exists {
					ids = append(ids, id)
				}
			}
			if err = r.removeDevices(ctx, ids, firewallID, &nf); err != nil {
				klog.Infof("[%s/%s] failed to remove nodebalancers from firewall - %s", nf.Namespace, nf.Name, err.Error())
				return
			}
			removeHostnames(&nf, removed)
			klog.Infof("[%s/%s] removed nodebalancers from firewall id=(%d) nodebalancers=(%v)", nf.Namespace, nf.Name, firewallID, ids)
		}
	}
	// On reconciliation success no need to reconcile unless triggered by Watch
	// Periodically we can reconcile to verify status
	klog.Infof("[%s/%s] reconcile complete firewall id=(%d)", nf.Namespace, nf.Name, firewallID)
	return ctrl.Result{
		Requeue:      false,
		RequeueAfter: 10 * time.Hour,
	}, nil
}

func removeHostnames(nf *alpha1v1.NodeBalancerFirewall, hostnamesToRemove []string) {
	for _, hostname := range hostnamesToRemove {
		nf.Status.NodeBalancerHostnames = removeItemString(nf.Status.NodeBalancerHostnames, hostname)
	}
}

func removeItemString(s []string, item string) []string {
	index := slices.Index(s, item)
	if index == -1 {
		return s // Item not found, return original slice
	}
	s[index] = s[len(s)-1]
	return s[:len(s)-1]
}

func getNodeBalancerIDs(ctx context.Context, r *NodeBalancerFirewallReconciler, nodes []string) (ids []int, err error) {
	nbMap, err := r.getNodeBalancerIDMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NodeBalancer ID mapping: %w", err)
	}

	// Convert hostnames to IDs
	ids = make([]int, 0, len(nodes))
	for _, hostname := range nodes {
		if id, exists := nbMap[hostname]; exists {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (r *NodeBalancerFirewallReconciler) createLinodeClient(opts internal.LinodeApiOptions) (err error) {
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

func nodeBalancerListChanges(ctx context.Context, nf alpha1v1.NodeBalancerFirewall, cli client.Client) (hostnames []string, added []string, removed []string, err error) {
	// Fetch LoadBalancer services from Kubernetes
	serviceList := &corev1.ServiceList{}
	if err = cli.List(ctx, serviceList); err != nil {
		err = fmt.Errorf("unable to get LoadBalancer services: %w", err)
		return
	}

	for _, svc := range serviceList.Items {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			// Use ExternalName if set, otherwise fall back to LoadBalancer IP
			if svc.Spec.ExternalName != "" {
				hostnames = append(hostnames, svc.Spec.ExternalName)
			} else if len(svc.Status.LoadBalancer.Ingress) > 0 {
				hostnames = append(hostnames, svc.Status.LoadBalancer.Ingress[0].Hostname)
			}
		}
	}

	// Detect newly added NodeBalancers
	for _, hostname := range hostnames {
		if !slices.Contains(nf.Status.NodeBalancerHostnames, hostname) {
			added = append(added, hostname)
		}
	}

	// Detect removed NodeBalancers
	for _, hostname := range nf.Status.NodeBalancerHostnames {
		if !slices.Contains(hostnames, hostname) {
			removed = append(removed, hostname)
		}
	}

	return hostnames, added, removed, nil
}

func (r *NodeBalancerFirewallReconciler) createFirewall(ctx context.Context, nodebalancers []int, nf *alpha1v1.NodeBalancerFirewall, rs lgo.FirewallRuleSet) (err error) {
	opts := lgo.FirewallCreateOptions{
		Label: fmt.Sprint("lke-nb-", r.ClusterID),
		Rules: rs,
		Devices: lgo.DevicesCreationOptions{
			NodeBalancers: nodebalancers,
		},
	}

	if firewall, err := r.lcli.CreateFirewall(ctx, opts); err != nil {
		return fmt.Errorf("failed to create firewall - %s", err.Error())
	} else {
		nf.Status.ID = strconv.Itoa(firewall.ID)
		nf.Status.NodeBalancerIDs = nodebalancers
	}
	return
}

func (r *NodeBalancerFirewallReconciler) getNodeBalancerIDMap(ctx context.Context) (map[string]int, error) {
	nbList, err := r.lcli.ListNodeBalancers(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to list NodeBalancers: %w", err)
	}

	// Reverse mapping: Hostname -> NodeBalancerID
	nbMap := make(map[string]int)
	for _, nb := range nbList {
		if nb.Hostname != nil {
			nbMap[*nb.Hostname] = nb.ID
		}
	}
	return nbMap, nil
}

func (r *NodeBalancerFirewallReconciler) checkOwnership(ctx context.Context, nf *alpha1v1.NodeBalancerFirewall) error {
	return checkOwnership(ctx, r, nf, r.Scheme)
}

func (r *NodeBalancerFirewallReconciler) checkFinalizer(ctx context.Context, nf *alpha1v1.NodeBalancerFirewall) (bool, error) {
	return checkFinalizer(ctx, r, nf, "nodebalancerfirewalls")
}

func (r *NodeBalancerFirewallReconciler) deleteExternalResources(ctx context.Context, nf FirewallObject) error {
	return deleteExternalResources(ctx, r, nf)
}

func (r *NodeBalancerFirewallReconciler) addDevices(ctx context.Context, nodes []int, firewallID int, nf *alpha1v1.NodeBalancerFirewall) error {
	return addDevices(ctx, r, nodes, firewallID, lgo.FirewallDeviceNodeBalancer, &nf.Status.NodeBalancerIDs)
}

func (r *NodeBalancerFirewallReconciler) removeDevices(ctx context.Context, nodes []int, firewallID int, nf *alpha1v1.NodeBalancerFirewall) error {
	return removeDevices(ctx, r, nodes, firewallID, &nf.Status.NodeBalancerIDs)
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeBalancerFirewallReconciler) SetupWithManager(mgr ctrl.Manager, opts internal.LinodeApiOptions) error {
	r.lApiOpts = opts

	return ctrl.NewControllerManagedBy(mgr).
		For(&alpha1v1.NodeBalancerFirewall{}).

		// Watch for LoadBalancer service changes to trigger reconciliation
		Watches(&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, svc client.Object) []reconcile.Request {
				service, ok := svc.(*corev1.Service)
				if !ok {
					return nil
				}

				// Only process LoadBalancer services
				if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
					return nil
				}

				klog.V(2).Infof("[%s/%s] LoadBalancer service updated", service.Namespace, service.Name)

				// Fetch all NodeBalancerFirewall objects
				nfList := &alpha1v1.NodeBalancerFirewallList{}
				if err := mgr.GetClient().List(ctx, nfList); err != nil {
					klog.Errorf("failed to list NodeBalancerFirewalls - %s", err.Error())
					return nil
				}

				// If no NodeBalancerFirewall objects exist, do nothing (don't create a default one)
				if len(nfList.Items) == 0 {
					klog.Infof("no NodeBalancerFirewalls found, skipping creation")
					return nil
				}

				// Schedule reconciliation for each existing NodeBalancerFirewall
				reqs := make([]reconcile.Request, 0, len(nfList.Items))
				for _, item := range nfList.Items {
					klog.Infof("[%s/%s] scheduling NodeBalancerFirewall reconciliation due to LoadBalancer service change", item.Namespace, item.Name)
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
