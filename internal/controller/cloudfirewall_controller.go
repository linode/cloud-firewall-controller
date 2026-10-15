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
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
	// Recorder records Events for refusals and unprotected nodes; nil disables them.
	Recorder events.EventRecorder
	// AutoCreateDefault makes the Node watch create an empty kube-system/primary
	// CloudFirewall when none exists. Disable it when a CloudFirewall with
	// firewall-id is delivered separately: an auto-created default object would
	// create and attach its own firewall, undoing import mode.
	AutoCreateDefault bool
}

// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls/finalizers,verbs=update

// Additional required resource permissions
// watch nodes
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
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
			return
		}
		statusChanged := !reflect.DeepEqual(cf.Status, original.Status)
		status := cf.Status
		if !reflect.DeepEqual(cf.ObjectMeta, original.ObjectMeta) {
			// If the metadata has changed we need to update the whole object. Update
			// does not write status (it is a subresource) and replaces cf with the
			// server's copy, so a status change made in the same reconcile is
			// written separately below rather than silently dropped.
			klog.V(1).Infof("[%s/%s] metadata change detected current(%+v) update(%+v)", cf.Namespace, cf.Name, original.ObjectMeta, cf.ObjectMeta)
			if e := r.Update(ctx, &cf); e != nil {
				err = fmt.Errorf("CloudFirewall update failed: err=%s", e)
				return
			}
		}
		if statusChanged {
			klog.V(1).Infof("[%s/%s] status change detected current(%+v) update(%+v)", cf.Namespace, cf.Name, original.Status, status)
			cf.Status = status
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

	if err = r.createLinodeClient(r.lApiOpts); err != nil {
		// can't proceed without valid Linode Creds, retry on exponential backoff
		klog.Errorf("[%s/%s] failed to get API credentials - %s", r.lApiOpts.Credentials, r.lApiOpts.CredentialsNs, err.Error())
		return
	}
	klog.Infof("[%s/%s] using credentials (%s/%s)", cf.Namespace, cf.Name, r.lApiOpts.Credentials, r.lApiOpts.CredentialsNs)

	// Deletion is handled first, ahead of the rate limiter: a deletion requeued
	// behind it can outlive the controller pod during an uninstall and leave the
	// object stuck terminating.
	if !cf.DeletionTimestamp.IsZero() {
		deleted = true
		return ctrl.Result{}, r.finalize(ctx, &cf)
	}

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
		klog.Errorf("[%s/%s] failed to convert FirewallRuleset - %s", cf.Namespace, cf.Name, err.Error())
		return ctrl.Result{}, err
	}

	// Rate limit how often we hit the Linode API
	// The incremental steps taken to add nodes to the cluster results in triggering several
	// reconciliations per node, which can hammer to API for a short period of time with Get calls.
	// In order to reduce that and give the scheduler a chance to flatten the reconcile calls this
	// introduces a small wait period. It also applies to import transitions, so a refused import
	// is not retried against the API on every Node event.
	minimumUpdateDuration := time.Second * 10
	if time.Since(cf.Status.LastUpdate.Time) < minimumUpdateDuration {
		klog.Infof("[%s/%s] update duration not met - requeuing %v", cf.Namespace, cf.Name, minimumUpdateDuration)
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
		}, nil
	}

	if changed, terr := r.reconcileImport(ctx, &cf, nodes, newRuleset); terr != nil || changed {
		return ctrl.Result{RequeueAfter: minimumUpdateDuration}, terr
	}

	if !cf.Exists() {
		if cf.ImportRequested() {
			// Unreachable while reconcileImport either succeeds or errors above;
			// kept so no future path can create a firewall in import mode.
			return ctrl.Result{}, nil
		}
		firewallLabel := fmt.Sprint("lke-", r.ClusterID)
		klog.Infof("[%s/%s] creating firewall label=(%s)", cf.Namespace, cf.Name, firewallLabel)
		if err = r.createFirewall(ctx, nodes, &cf, newRuleset); err != nil {
			klog.Errorf("[%s/%s] %s", cf.Namespace, cf.Name, err.Error())
			r.event(&cf, corev1.EventTypeWarning, "CreateFailed", err.Error())
		}
		return ctrl.Result{}, err
	}

	var firewall *lgo.Firewall
	firewallID, err := cf.GetID()
	if err != nil {
		klog.Errorf("[%s/%s] failed to get firewallID - %s", cf.Namespace, cf.Name, err.Error())
		return
	}

	if err = r.checkOwnership(ctx, &cf); err != nil {
		klog.Errorf("[%s/%s] failed ownership check - %s", cf.Namespace, cf.Name, err.Error())
		return ctrl.Result{
			RequeueAfter: minimumUpdateDuration,
		}, err
	}

	klog.Infof("[%s/%s] getting firewall id=(%d)", cf.Namespace, cf.Name, firewallID)
	firewall, err = r.lcli.GetFirewall(ctx, firewallID)
	if err != nil {
		if FirewallIsNotFound(err) {
			if cf.MarkedImported() {
				// The controller does not own an imported firewall, so it must not
				// replace it with one it does own.
				err = fmt.Errorf("imported firewall id=(%d) not found", firewallID)
				klog.Errorf("[%s/%s] %s - not recreating", cf.Namespace, cf.Name, err.Error())
				r.setCondition(&cf, alpha1v1.ConditionImported, metav1.ConditionFalse, "NotFound", err.Error())
				return ctrl.Result{}, err
			}
			klog.Infof("[%s/%s] firewall id=(%d) not found - recreating", cf.Namespace, cf.Name, firewallID)
			if err = r.createFirewall(ctx, nodes, &cf, newRuleset); err != nil {
				klog.Errorf("[%s/%s] %s", cf.Namespace, cf.Name, err.Error())
				r.event(&cf, corev1.EventTypeWarning, "CreateFailed", err.Error())
			}
			// Either a firewall was created with the right node list or an error occured
			return
		}
		klog.Errorf("[%s/%s] failed to get firewall id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
		return ctrl.Result{}, err
	}

	// Ownership is decided from the firewall itself, never from the absence of an
	// import marker: only a firewall the controller created (label lke-<clusterID>)
	// gets its devices managed and a finalizer that deletes it.
	owned := r.owns(&cf, firewall)
	if owned {
		controllerutil.AddFinalizer(&cf, finalizerName)
	} else {
		// Nothing to clean up for a firewall the controller did not create, and a
		// finalizer would only risk leaving the object stuck on uninstall.
		controllerutil.RemoveFinalizer(&cf, finalizerName)
	}

	if !equalFirewallRuleSets(&firewall.Rules, &newRuleset) {
		klog.Infof("[%s/%s] changes found in firewall rules id=(%d)", cf.Namespace, cf.Name, firewallID)
		if _, err = r.lcli.UpdateFirewallRules(ctx, firewallID, newRuleset); err != nil {
			klog.Errorf("[%s/%s] failed to update firewall rules id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return
		}
		klog.Infof("[%s/%s] updated firewall rules id=(%d)", cf.Namespace, cf.Name, firewallID)
	} else {
		klog.Infof("[%s/%s] firewall rules are up-to-date id=(%d)", cf.Namespace, cf.Name, firewallID)
	}

	if owned {
		if err = r.syncDevices(ctx, &cf, firewallID, added, removed); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		r.reportDevices(ctx, &cf, firewallID, nodes)
	}
	// On reconciliation success no need to reconcile unless triggered by Watch
	// Periodically we can reconcile to verify status
	klog.Infof("[%s/%s] reconcile complete firewall id=(%d)", cf.Namespace, cf.Name, firewallID)
	return ctrl.Result{
		RequeueAfter: 10 * time.Hour,
	}, nil
}

// owns reports whether fw is a firewall this controller created for this
// cluster: one it labels lke-<clusterID> on creation, and not recorded as
// adopted or named by .spec.firewall-id. It reads the firewall itself rather
// than inferring ownership from a missing marker.
func (r *CloudFirewallReconciler) owns(cf *alpha1v1.CloudFirewall, fw *lgo.Firewall) bool {
	return !cf.MarkedImported() && fw.Label == fmt.Sprint("lke-", r.ClusterID)
}

// finalize handles a CloudFirewall being deleted: it deletes the firewall only
// when the controller created it, then drops the finalizer.
func (r *CloudFirewallReconciler) finalize(ctx context.Context, cf *alpha1v1.CloudFirewall) error {
	if !controllerutil.ContainsFinalizer(cf, finalizerName) {
		return nil
	}
	ctx = context.WithoutCancel(ctx)
	if cf.Exists() && !cf.MarkedImported() {
		id, err := cf.GetID()
		if err != nil {
			return err
		}
		fw, err := r.lcli.GetFirewall(ctx, id)
		switch {
		case err != nil && FirewallIsNotFound(err):
			klog.Infof("[%s/%s] firewall id=(%d) already gone", cf.Namespace, cf.Name, id)
		case err != nil:
			return fmt.Errorf("failed to get firewall id=(%d) - %s", id, err.Error())
		case r.owns(cf, fw):
			if err := r.lcli.DeleteFirewall(ctx, id); err != nil && !FirewallIsNotFound(err) {
				return err
			}
			klog.Infof("[%s/%s] firewall deleted id=(%d)", cf.Namespace, cf.Name, id)
		default:
			klog.Infof("[%s/%s] not deleting firewall id=(%d) label=(%s): not created by this controller", cf.Namespace, cf.Name, id, fw.Label)
		}
	} else {
		klog.Infof("[%s/%s] not deleting imported firewall id=(%s)", cf.Namespace, cf.Name, cf.Status.ID)
	}
	return r.removeFinalizer(ctx, cf)
}

// syncDevices attaches added nodes to and detaches removed nodes from a firewall
// the controller owns.
func (r *CloudFirewallReconciler) syncDevices(ctx context.Context, cf *alpha1v1.CloudFirewall, firewallID int, added, removed []int) error {
	if len(added) != 0 {
		if err := r.addNodes(ctx, added, firewallID, cf); err != nil {
			klog.Errorf("[%s/%s] failed to add nodes to firewall id=(%d) - %s", cf.Namespace, cf.Name, firewallID, err.Error())
			return err
		}
		klog.Infof("[%s/%s] added nodes to firewall id=(%d) nodes=(%v)", cf.Namespace, cf.Name, firewallID, added)
	}

	if len(removed) != 0 {
		if err := r.removeNodes(ctx, removed, firewallID, cf); err != nil {
			klog.Errorf("[%s/%s] failed to remove nodes from firewall - %s", cf.Namespace, cf.Name, err.Error())
			return err
		}
		klog.Infof("[%s/%s] removed nodes from firewall id=(%d) nodes=(%v)", cf.Namespace, cf.Name, firewallID, removed)
	}
	return nil
}

// reportDevices leaves the devices of a firewall the controller does not own
// alone (attachment belongs to whoever attached it, for example an LKE node
// pool's firewall_id, which also attaches every node the pool adds) and reports
// nodes it does not protect and devices outside the cluster it now also governs.
func (r *CloudFirewallReconciler) reportDevices(ctx context.Context, cf *alpha1v1.CloudFirewall, firewallID int, nodes []int) {
	klog.Infof("[%s/%s] firewall id=(%d) not created by this controller - not managing devices", cf.Namespace, cf.Name, firewallID)
	devices, err := r.lcli.ListFirewallDevices(ctx, firewallID, nil)
	if err != nil {
		msg := fmt.Sprintf("could not list devices of firewall id=(%d) - %s", firewallID, err.Error())
		klog.Warningf("[%s/%s] %s", cf.Namespace, cf.Name, msg)
		r.setCondition(cf, alpha1v1.ConditionNodesProtected, metav1.ConditionUnknown, "DevicesUnavailable", msg)
		return
	}
	attached := map[int]bool{}
	for _, d := range devices {
		if l, ok := deviceLinodeID(d); ok {
			attached[l] = true
		}
	}
	var unprotected []int
	for _, n := range nodes {
		if !attached[n] {
			unprotected = append(unprotected, n)
		}
	}
	if len(unprotected) > 0 {
		msg := fmt.Sprintf("nodes %v are not attached to firewall id=(%d) and are not protected by it", unprotected, firewallID)
		klog.Warningf("[%s/%s] %s", cf.Namespace, cf.Name, msg)
		r.setCondition(cf, alpha1v1.ConditionNodesProtected, metav1.ConditionFalse, "NodesNotAttached", msg)
		r.event(cf, corev1.EventTypeWarning, "NodesNotAttached", msg)
	} else {
		r.setCondition(cf, alpha1v1.ConditionNodesProtected, metav1.ConditionTrue, "AllNodesAttached",
			fmt.Sprintf("all %d nodes are attached to firewall id=(%d)", len(nodes), firewallID))
	}
	if foreign, err := r.foreignDevices(ctx, devices, nodes); err == nil && len(foreign) > 0 {
		msg := fmt.Sprintf("firewall id=(%d) is also attached to devices outside this cluster %v, which receive this cluster's rules", firewallID, foreign)
		klog.Warningf("[%s/%s] %s", cf.Namespace, cf.Name, msg)
		r.event(cf, corev1.EventTypeWarning, "ForeignDevices", msg)
	}
}

func remove(s []int, i int) []int {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

func (r *CloudFirewallReconciler) checkOwnership(ctx context.Context, cf *alpha1v1.CloudFirewall) error {
	owner := metav1.GetControllerOf(cf)
	if owner != nil {
		return nil
	}

	// If the CloudFirewall has no owner attach it to this controller so it can be garbage
	// collected if the controller is deleted.
	ctrlDpl := appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      "cloud-firewall-controller",
		Namespace: "kube-system",
	},
		&ctrlDpl)
	if err != nil {
		return fmt.Errorf("failed to get controller deployment: %s", err.Error())
	}

	klog.Infof("[%s/%s] set controller reference controller=(%s/%s)", cf.Namespace, cf.Name, ctrlDpl.Namespace, ctrlDpl.Name)
	if err = ctrl.SetControllerReference(&ctrlDpl, cf, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %s", err.Error())
	}

	return nil
}

const finalizerName = "cloudfirewalls.networking.linode.com/finalizer"

// removeFinalizer drops the controller's finalizer without touching any firewall.
// An error is returned so the deletion is retried rather than left stuck.
func (r *CloudFirewallReconciler) removeFinalizer(ctx context.Context, cf *alpha1v1.CloudFirewall) error {
	if controllerutil.RemoveFinalizer(cf, finalizerName) {
		if err := r.Update(context.WithoutCancel(ctx), cf); err != nil {
			return fmt.Errorf("failed to remove finalizer - %s", err.Error())
		}
	}
	return nil
}

// removeNodes detaches nodes from a firewall. The Linode API addresses a firewall
// device by its device ID, not by the Linode ID, so the device is looked up first;
// a node that is already detached is just dropped from status.
func (r *CloudFirewallReconciler) removeNodes(ctx context.Context, nodes []int, firewallID int, cf *alpha1v1.CloudFirewall) error {
	devices, err := r.lcli.ListFirewallDevices(ctx, firewallID, nil)
	if err != nil {
		return fmt.Errorf("failed to list devices of firewall (%d) - %s", firewallID, err.Error())
	}
	for _, node := range nodes {
		if d, ok := deviceForLinode(devices, node); ok {
			if err := r.lcli.DeleteFirewallDevice(ctx, firewallID, d.ID); err != nil && !FirewallIsNotFound(err) {
				return fmt.Errorf("failed to remove device (%d) linode (%d) from firewall (%d) - %s", d.ID, node, firewallID, err.Error())
			}
		}
		// Remove the node from status list
		if idx := slices.Index(cf.Status.Nodes, node); idx >= 0 {
			cf.Status.Nodes = remove(cf.Status.Nodes, idx)
		}
	}
	return nil
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

// reconcileImport applies firewall-id transitions and reports whether it changed
// anything. An adopted firewall is recorded in the ImportedAnnotation. A
// transition only updates the marker and status; the caller requeues and the
// next reconcile applies rules through the normal path.
func (r *CloudFirewallReconciler) reconcileImport(ctx context.Context, cf *alpha1v1.CloudFirewall, nodes []int, rs lgo.FirewallRuleSet) (bool, error) {
	if cf.ImportRequested() && (cf.Status.ID != cf.Spec.ImportID || cf.ImportedID() != cf.Spec.ImportID) {
		if err := r.importFirewall(ctx, cf, nodes, rs); err != nil {
			klog.Errorf("[%s/%s] failed to import firewall - %s", cf.Namespace, cf.Name, err.Error())
			r.setCondition(cf, alpha1v1.ConditionImported, metav1.ConditionFalse, "ImportRefused", err.Error())
			r.event(cf, corev1.EventTypeWarning, "ImportRefused", err.Error())
			return false, err
		}
		msg := fmt.Sprintf("managing the rules of firewall id=(%s)", cf.Spec.ImportID)
		r.setCondition(cf, alpha1v1.ConditionImported, metav1.ConditionTrue, "Adopted", msg)
		r.event(cf, corev1.EventTypeNormal, "Adopted", msg)
		return true, nil
	}
	if !cf.ImportRequested() && cf.ImportedID() != "" {
		releaseImportedFirewall(cf)
		meta.RemoveStatusCondition(&cf.Status.Conditions, alpha1v1.ConditionImported)
		meta.RemoveStatusCondition(&cf.Status.Conditions, alpha1v1.ConditionNodesProtected)
		return true, nil
	}
	return false, nil
}

// validateImportSpec enforces, for CRDs that predate the schema rules, what the
// CRD's validation rules enforce at admission: import mode needs an explicit
// defaultRules, and defaultRules=false needs inbound rules. Importing replaces
// the firewall's whole ruleset, and an empty inbound ruleset under the DROP
// policy cuts the nodes off from the control plane.
func validateImportSpec(spec alpha1v1.CloudFirewallSpec) error {
	if spec.DefaultRules == nil {
		return fmt.Errorf("defaultRules must be set explicitly when firewall-id is set")
	}
	if !*spec.DefaultRules && len(spec.Ruleset.Inbound) == 0 {
		return fmt.Errorf("with firewall-id set and defaultRules false, ruleset.inbound must list the rules the firewall needs")
	}
	return nil
}

// importFirewall adopts the existing firewall named by .spec.firewall-id and
// records it in the ImportedAnnotation. It never creates a firewall.
//
// It refuses a firewall attached to any device outside this cluster. Adopting
// replaces the firewall's whole ruleset, so a shared firewall (another cluster's
// node pool, a standalone Linode, a NodeBalancer) would have its rules replaced
// too, and two clusters' controllers would overwrite each other on every
// reconcile. A mistyped ID looks the same way. A Linode that belongs to this LKE
// cluster but has not registered as a Node yet (or is being removed) is not
// foreign.
//
// If the controller currently owns a firewall it created (switching an existing
// install to firewall-id), the nodes are moved onto the imported firewall, after
// its rules are applied, and only then is the old firewall deleted. This is the
// one time the controller changes an imported firewall's devices: without it the
// nodes would be left with no firewall at all, because a Linode can only be
// attached to one Cloud Firewall.
func (r *CloudFirewallReconciler) importFirewall(ctx context.Context, cf *alpha1v1.CloudFirewall, nodes []int, rs lgo.FirewallRuleSet) error {
	if err := validateImportSpec(cf.Spec); err != nil {
		return err
	}
	id, err := strconv.Atoi(cf.Spec.ImportID)
	if err != nil {
		return fmt.Errorf("invalid firewall-id (%s) - %s", cf.Spec.ImportID, err.Error())
	}
	if _, err = r.lcli.GetFirewall(ctx, id); err != nil {
		return fmt.Errorf("failed to get firewall id=(%d) - %s", id, err.Error())
	}
	devices, err := r.lcli.ListFirewallDevices(ctx, id, nil)
	if err != nil {
		return fmt.Errorf("failed to list devices of firewall id=(%d) - %s", id, err.Error())
	}
	foreign, err := r.foreignDevices(ctx, devices, nodes)
	if err != nil {
		return err
	}
	if len(foreign) > 0 {
		return fmt.Errorf("firewall id=(%d) is attached to devices that are not nodes of this cluster %v; refusing to adopt it "+
			"because its rules would be replaced for them too", id, foreign)
	}

	if cf.Exists() && cf.Status.ID != cf.Spec.ImportID && cf.Status.ID != cf.ImportedID() {
		oldID, err := cf.GetID()
		if err != nil {
			return err
		}
		old, err := r.lcli.GetFirewall(ctx, oldID)
		switch {
		case err != nil && FirewallIsNotFound(err):
		case err != nil:
			return fmt.Errorf("failed to get firewall id=(%d) - %s", oldID, err.Error())
		case r.owns(cf, old):
			if err := r.moveNodes(ctx, cf, oldID, id, nodes, rs); err != nil {
				return err
			}
			klog.Infof("[%s/%s] deleting controller-created firewall id=(%d) in favour of imported firewall id=(%d)", cf.Namespace, cf.Name, oldID, id)
			if err := r.lcli.DeleteFirewall(ctx, oldID); err != nil && !FirewallIsNotFound(err) {
				return fmt.Errorf("failed to delete controller-created firewall id=(%d) - %s", oldID, err.Error())
			}
		default:
			klog.Infof("[%s/%s] leaving previous firewall id=(%d) label=(%s) in place: not created by this controller", cf.Namespace, cf.Name, oldID, old.Label)
		}
	}

	klog.Infof("[%s/%s] imported firewall id=(%d)", cf.Namespace, cf.Name, id)
	if cf.Annotations == nil {
		cf.Annotations = map[string]string{}
	}
	cf.Annotations[alpha1v1.ImportedAnnotation] = cf.Spec.ImportID
	cf.Status.ID = cf.Spec.ImportID
	// Device membership of an imported firewall is not tracked.
	cf.Status.Nodes = nil
	return nil
}

// moveNodes moves the cluster's nodes from the controller-created firewall
// oldID to newID. The rules go on newID first so nodes land on the ruleset
// they need, and each node is detached and re-attached in turn, so no node
// is ever without a firewall for longer than that pair of calls. It is
// idempotent: a retry after a partial move picks up where it stopped.
func (r *CloudFirewallReconciler) moveNodes(ctx context.Context, cf *alpha1v1.CloudFirewall, oldID, newID int, nodes []int, rs lgo.FirewallRuleSet) error {
	if _, err := r.lcli.UpdateFirewallRules(ctx, newID, rs); err != nil {
		return fmt.Errorf("failed to apply rules to firewall id=(%d) before moving nodes - %s", newID, err.Error())
	}
	oldDevices, err := r.lcli.ListFirewallDevices(ctx, oldID, nil)
	if err != nil {
		return fmt.Errorf("failed to list devices of firewall id=(%d) - %s", oldID, err.Error())
	}
	newDevices, err := r.lcli.ListFirewallDevices(ctx, newID, nil)
	if err != nil {
		return fmt.Errorf("failed to list devices of firewall id=(%d) - %s", newID, err.Error())
	}
	for _, n := range nodes {
		if _, ok := deviceForLinode(newDevices, n); ok {
			continue
		}
		if d, ok := deviceForLinode(oldDevices, n); ok {
			if err := r.lcli.DeleteFirewallDevice(ctx, oldID, d.ID); err != nil && !FirewallIsNotFound(err) {
				return fmt.Errorf("failed to detach linode (%d) from firewall id=(%d) - %s", n, oldID, err.Error())
			}
		}
		if _, err := r.lcli.CreateFirewallDevice(ctx, newID, lgo.FirewallDeviceCreateOptions{ID: n, Type: lgo.FirewallDeviceLinode}); err != nil {
			return fmt.Errorf("failed to attach linode (%d) to firewall id=(%d); it has no firewall until this is retried - %s", n, newID, err.Error())
		}
		klog.Infof("[%s/%s] moved linode (%d) from firewall id=(%d) to id=(%d)", cf.Namespace, cf.Name, n, oldID, newID)
	}
	return nil
}

// foreignDevices returns the devices that are not nodes of this cluster. A
// Linode that is not a registered Node is checked against the LKE cluster it
// belongs to, so a node still joining or leaving the cluster is not foreign.
func (r *CloudFirewallReconciler) foreignDevices(ctx context.Context, devices []lgo.FirewallDevice, nodes []int) ([]string, error) {
	clusterID, _ := strconv.Atoi(r.ClusterID)
	var foreign []string
	for _, d := range devices {
		l, ok := deviceLinodeID(d)
		if ok && slices.Contains(nodes, l) {
			continue
		}
		if ok && clusterID != 0 {
			inst, err := r.lcli.GetInstance(ctx, l)
			if err != nil {
				return nil, fmt.Errorf("failed to look up linode (%d) attached to the firewall - %s", l, err.Error())
			}
			if inst.LKEClusterID == clusterID {
				continue
			}
		}
		foreign = append(foreign, fmt.Sprintf("%s:%d", d.Entity.Type, d.Entity.ID))
	}
	return foreign, nil
}

// releaseImportedFirewall forgets an adopted firewall after .spec.firewall-id is
// removed. The firewall and its rules and devices are left exactly as they are;
// the controller then creates its own firewall as it would for a new object.
func releaseImportedFirewall(cf *alpha1v1.CloudFirewall) {
	imported := cf.ImportedID()
	klog.Warningf("[%s/%s] firewall-id removed - releasing imported firewall id=(%s), which is left in place. The controller now "+
		"creates and attaches its own firewall; if a node pool still attaches firewall %s, that will fail until it is detached",
		cf.Namespace, cf.Name, imported, imported)
	delete(cf.Annotations, alpha1v1.ImportedAnnotation)
	if cf.Status.ID == imported {
		cf.Status.ID = ""
		cf.Status.Nodes = nil
	}
}

// setCondition records a status condition; LastTransitionTime only moves when the
// status changes, so repeated reconciles do not churn status.
func (r *CloudFirewallReconciler) setCondition(cf *alpha1v1.CloudFirewall, t string, s metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&cf.Status.Conditions, metav1.Condition{
		Type: t, Status: s, Reason: reason, Message: msg, ObservedGeneration: cf.Generation,
	})
}

// event records a Kubernetes Event on the object when a recorder is configured.
func (r *CloudFirewallReconciler) event(cf *alpha1v1.CloudFirewall, eventType, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Eventf(cf, nil, eventType, reason, "Reconcile", "%s", msg)
	}
}

// deviceLinodeID returns the Linode a firewall device belongs to: the device
// itself for a linode device, or its parent for a Linode interface device.
func deviceLinodeID(d lgo.FirewallDevice) (int, bool) {
	if d.Entity.Type == lgo.FirewallDeviceLinode {
		return d.Entity.ID, true
	}
	if p := d.Entity.ParentEntity; p != nil && p.Type == lgo.FirewallDeviceLinode {
		return p.ID, true
	}
	return 0, false
}

// deviceForLinode returns the firewall device that attaches the given Linode.
func deviceForLinode(devices []lgo.FirewallDevice, linodeID int) (lgo.FirewallDevice, bool) {
	for _, d := range devices {
		if l, ok := deviceLinodeID(d); ok && l == linodeID {
			return d, true
		}
	}
	return lgo.FirewallDevice{}, false
}

func (r *CloudFirewallReconciler) createFirewall(ctx context.Context, nodes []int, cf *alpha1v1.CloudFirewall, rs lgo.FirewallRuleSet) (err error) {
	opts := lgo.FirewallCreateOptions{
		Label: fmt.Sprint("lke-", r.ClusterID),
		Rules: rs,
		Devices: lgo.DevicesCreationOptions{
			Linodes: nodes,
		},
	}
	var firewall *lgo.Firewall
	if firewall, err = r.lcli.CreateFirewall(ctx, opts); err != nil {
		err = fmt.Errorf("failed to create firewall - %s (if the nodes are already attached to another Cloud Firewall, "+
			"for example a node pool's firewall_id, set spec.firewall-id to manage that firewall instead)", err.Error())
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
	if !ok {
		return false
	}
	klog.Infof("linode client error (%+v)", originalErr.Code)
	return originalErr.Code == 404
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
				return r.mapNodeEvent(ctx, mgr.GetClient(), node)
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

// mapNodeEvent turns a Node event into reconcile requests for every
// CloudFirewall, creating the default kube-system/primary object first when none
// exists and AutoCreateDefault allows it.
func (r *CloudFirewallReconciler) mapNodeEvent(ctx context.Context, c client.Client, node client.Object) []reconcile.Request {
	klog.V(2).Infof("[%s] node updated: %s", node.GetNamespace(), node.GetName())
	latestRevision := rules.LatestRevision()
	previousRevisions := rules.PreviousRevisions()
	cfList := &alpha1v1.CloudFirewallList{}
	if err := c.List(ctx, cfList); err != nil {
		klog.Errorf("failed to list CloudFirewalls - %s", err.Error())
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(cfList.Items))
	// If for any reason no default CloudFirewall object exists attempt to create it,
	// unless that is disabled because the object is delivered separately.
	if len(cfList.Items) == 0 && !r.AutoCreateDefault {
		klog.Infof("no CloudFirewalls found; auto-create of the default object is disabled")
		return reqs
	}
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
		if err := c.Create(ctx, cfObj); err != nil {
			klog.Errorf("[%s/%s] failed to create default CloudFirewall - %s", cfObj.Namespace, cfObj.Name, err.Error())
		}
		// No need to schedule a reconcile here, the creation of the object will generate a reconciliation
		return reqs
	}

	for _, item := range cfList.Items {
		if item.ImportRequested() {
			// Never migrate an import-mode object onto the default ruleset: its
			// defaultRules/ruleset were chosen for the imported firewall.
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: item.GetNamespace(), Name: item.GetName(),
			}})
			continue
		}

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
				if err := c.Update(ctx, &item); err != nil {
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
}
