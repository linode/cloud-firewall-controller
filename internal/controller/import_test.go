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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	lgo "github.com/linode/linodego"

	alpha1v1 "github.com/linode/cloud-firewall-controller/api/alpha1v1"
	internal "github.com/linode/cloud-firewall-controller/internal/types"
)

const (
	// clusterNode is the Linode ID of the one Node the specs create, in LKE
	// cluster clusterID.
	clusterNode = 111
	clusterID   = "123"
	// ownedLabel is the label the controller gives firewalls it creates.
	ownedLabel = "lke-" + clusterID
	poolLabel  = "pool-firewall"
	kindLinode = "linode"
)

// fakeDevice is one device attached to a fake firewall. kind is "linode",
// "iface" (a Linode interface whose parent is the Linode) or "nodebalancer".
type fakeDevice struct {
	id     int
	kind   string
	linode int
}

type fakeFirewall struct {
	label   string
	devices []fakeDevice
	rules   json.RawMessage
}

// fakeLinodeAPI serves the Linode endpoints the reconciler calls, keeps state
// (labels, stored rules, devices) so idempotence and moves can be asserted, and
// records every request so a spec can assert which calls were (not) made.
// instances maps a Linode ID to the LKE cluster it belongs to.
type fakeLinodeAPI struct {
	mu         sync.Mutex
	requests   []string // "METHOD /path"
	firewalls  map[string]*fakeFirewall
	instances  map[int]int
	nextDevice int
	nextFW     int
}

func (f *fakeLinodeAPI) fw(id, label string, devices ...fakeDevice) {
	for i := range devices {
		f.nextDevice++
		devices[i].id = f.nextDevice
	}
	f.firewalls[id] = &fakeFirewall{label: label, devices: devices}
}

func linode(id int) fakeDevice { return fakeDevice{kind: kindLinode, linode: id} }
func iface(id int) fakeDevice  { return fakeDevice{kind: "iface", linode: id} }

func (d fakeDevice) json() string {
	switch d.kind {
	case "iface":
		return fmt.Sprintf(`{"id":%d,"entity":{"id":9%d,"type":"linode_interface","label":"eth1",`+
			`"parent_entity":{"id":%d,"type":"linode","label":"n%d"}}}`, d.id, d.linode, d.linode, d.linode)
	default:
		return fmt.Sprintf(`{"id":%d,"entity":{"id":%d,"type":%q,"label":"d%d"}}`, d.id, d.linode, d.kind, d.linode)
	}
}

func writeErr(w http.ResponseWriter, code int, reason string) {
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"errors":[{"reason":%q}]}`, reason)
}

func (f *fakeLinodeAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req.Method+" "+req.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(req.Body)

	if l, ok := strings.CutPrefix(req.URL.Path, "/v4/linode/instances/"); ok {
		id, _ := strconv.Atoi(l)
		cluster, ok := f.instances[id]
		if !ok {
			writeErr(w, http.StatusNotFound, "Not found")
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":%d,"label":"n%d","lke_cluster_id":%d}`, id, id, cluster)
		return
	}
	if req.URL.Path == "/v4/networking/firewalls" && req.Method == http.MethodPost {
		var opts lgo.FirewallCreateOptions
		_ = json.Unmarshal(body, &opts)
		f.nextFW++
		id := strconv.Itoa(800 + f.nextFW)
		var devs []fakeDevice
		for _, l := range opts.Devices.Linodes {
			devs = append(devs, linode(l))
		}
		f.fw(id, opts.Label, devs...)
		rules, _ := json.Marshal(opts.Rules)
		f.firewalls[id].rules = rules
		_, _ = fmt.Fprintf(w, `{"id":%s,"label":%q,"status":"enabled"}`, id, opts.Label)
		return
	}

	id, rest, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, "/v4/networking/firewalls/"), "/")
	fw, ok := f.firewalls[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "Not found")
		return
	}
	switch {
	case req.Method == http.MethodGet && rest == "":
		rules := fw.rules
		if rules == nil {
			rules = json.RawMessage(`{"inbound":[],"inbound_policy":"DROP","outbound":[],"outbound_policy":"ACCEPT"}`)
		}
		_, _ = fmt.Fprintf(w, `{"id":%s,"label":%q,"status":"enabled","rules":%s}`, id, fw.label, rules)
	case req.Method == http.MethodPut && rest == "rules":
		fw.rules = body
		_, _ = w.Write(body)
	case req.Method == http.MethodDelete && rest == "":
		delete(f.firewalls, id)
		_, _ = io.WriteString(w, `{}`)
	case req.Method == http.MethodGet && rest == "devices":
		data := make([]string, 0, len(fw.devices))
		for _, d := range fw.devices {
			data = append(data, d.json())
		}
		_, _ = fmt.Fprintf(w, `{"data":[%s],"page":1,"pages":1,"results":%d}`, strings.Join(data, ","), len(fw.devices))
	case req.Method == http.MethodPost && rest == "devices":
		var opts lgo.FirewallDeviceCreateOptions
		_ = json.Unmarshal(body, &opts)
		f.nextDevice++
		d := fakeDevice{id: f.nextDevice, kind: kindLinode, linode: opts.ID}
		fw.devices = append(fw.devices, d)
		_, _ = io.WriteString(w, d.json())
	case req.Method == http.MethodDelete && strings.HasPrefix(rest, "devices/"):
		devID, _ := strconv.Atoi(strings.TrimPrefix(rest, "devices/"))
		for i, d := range fw.devices {
			if d.id == devID {
				fw.devices = append(fw.devices[:i], fw.devices[i+1:]...)
				_, _ = io.WriteString(w, `{}`)
				return
			}
		}
		writeErr(w, http.StatusNotFound, "Not found")
	default:
		writeErr(w, http.StatusInternalServerError, "unexpected call in test")
	}
}

// mutating returns the recorded requests that create or delete a firewall or
// change a firewall's devices. Reading is not mutating; neither is PUT rules.
func (f *fakeLinodeAPI) mutating() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if r == "POST /v4/networking/firewalls" || strings.HasPrefix(r, "DELETE ") ||
			(strings.Contains(r, "/devices") && !strings.HasPrefix(r, "GET ")) {
			out = append(out, r)
		}
	}
	return out
}

// count returns how many times a request was made.
func (f *fakeLinodeAPI) count(req string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == req {
			n++
		}
	}
	return n
}

// linodesOn returns the Linode IDs attached to a fake firewall.
func (f *fakeLinodeAPI) linodesOn(id string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int
	if fw, ok := f.firewalls[id]; ok {
		for _, d := range fw.devices {
			out = append(out, d.linode)
		}
	}
	return out
}

func TestDeviceLinodeID(t *testing.T) {
	parent := &lgo.FirewallDeviceEntity{ID: 111, Type: lgo.FirewallDeviceLinode}
	for name, tc := range map[string]struct {
		device lgo.FirewallDevice
		id     int
		ok     bool
	}{
		"linode":            {lgo.FirewallDevice{Entity: lgo.FirewallDeviceEntity{ID: 111, Type: lgo.FirewallDeviceLinode}}, 111, true},
		"linode interface":  {lgo.FirewallDevice{Entity: lgo.FirewallDeviceEntity{ID: 9, Type: lgo.FirewallDeviceLinodeInterface, ParentEntity: parent}}, 111, true},
		"orphan interface":  {lgo.FirewallDevice{Entity: lgo.FirewallDeviceEntity{ID: 9, Type: lgo.FirewallDeviceLinodeInterface}}, 0, false},
		"nodebalancer":      {lgo.FirewallDevice{Entity: lgo.FirewallDeviceEntity{ID: 5, Type: lgo.FirewallDeviceNodeBalancer}}, 0, false},
		"non-linode parent": {lgo.FirewallDevice{Entity: lgo.FirewallDeviceEntity{ID: 9, Type: lgo.FirewallDeviceLinodeInterface, ParentEntity: &lgo.FirewallDeviceEntity{ID: 5, Type: lgo.FirewallDeviceNodeBalancer}}}, 0, false},
	} {
		if id, ok := deviceLinodeID(tc.device); id != tc.id || ok != tc.ok {
			t.Errorf("%s: deviceLinodeID = (%d, %v), want (%d, %v)", name, id, ok, tc.id, tc.ok)
		}
	}
}

func TestValidateImportSpec(t *testing.T) {
	yes, no := true, false
	rule := alpha1v1.RuleSpec{Label: "a", Action: "ACCEPT", Protocol: "TCP"}
	for name, tc := range map[string]struct {
		spec alpha1v1.CloudFirewallSpec
		ok   bool
	}{
		"defaultRules unset":           {alpha1v1.CloudFirewallSpec{ImportID: "1"}, false},
		"defaultRules true":            {alpha1v1.CloudFirewallSpec{ImportID: "1", DefaultRules: &yes}, true},
		"defaultRules false, no rules": {alpha1v1.CloudFirewallSpec{ImportID: "1", DefaultRules: &no}, false},
		"defaultRules false, rules":    {alpha1v1.CloudFirewallSpec{ImportID: "1", DefaultRules: &no, Ruleset: alpha1v1.RulesetSpec{Inbound: []alpha1v1.RuleSpec{rule}}}, true},
	} {
		if err := validateImportSpec(tc.spec); (err == nil) != tc.ok {
			t.Errorf("%s: validateImportSpec = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

var _ = Describe("CloudFirewall Controller with an imported firewall", func() {
	Context("with the current CRD", func() {
		importSpecs(func() client.Client { return k8sClient }, true)
	})
	// The CRD and controller ship as separate charts (and apl-core vendors the
	// CRD under crds/, which Helm never upgrades). Ownership must not depend on
	// anything an older CRD's schema would prune.
	Context("with a CRD from before firewall-id was supported", func() {
		importSpecs(func() client.Client { return legacyClient }, false)
	})
})

// importSpecs registers the import-mode specs against the API server kc returns.
// strictCRD is true when that server's CRD has this change's schema (validation
// rules and status conditions).
func importSpecs(kc func() client.Client, strictCRD bool) {
	const (
		// CloudFirewall objects live beside the controller Deployment, which
		// checkOwnership makes their owner (owner refs cannot cross namespaces).
		ns       = "kube-system"
		credName = "linode-test-creds"
	)
	ctx := context.Background()

	var (
		api        *fakeLinodeAPI
		reconciler *CloudFirewallReconciler
		cleanup    []client.Object
	)

	// ensure creates obj unless it already exists and removes it after the spec.
	ensure := func(obj client.Object) {
		if err := kc().Create(ctx, obj); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		cleanup = append(cleanup, obj)
	}

	// The reconciler rate-limits itself to one Linode round per 10s per object;
	// age LastUpdate so each step below is a full reconcile.
	reconcileOnce := func(nn types.NamespacedName) error {
		cf := &alpha1v1.CloudFirewall{}
		if err := kc().Get(ctx, nn, cf); err == nil {
			cf.Status.LastUpdate = metav1.NewTime(time.Now().Add(-time.Minute))
			Expect(kc().Status().Update(ctx, cf)).To(Succeed())
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
		return err
	}

	get := func(nn types.NamespacedName) *alpha1v1.CloudFirewall {
		cf := &alpha1v1.CloudFirewall{}
		Expect(kc().Get(ctx, nn, cf)).To(Succeed())
		return cf
	}

	expectCondition := func(nn types.NamespacedName, t string, s metav1.ConditionStatus, reason string) {
		if !strictCRD {
			return // an older CRD prunes status.conditions
		}
		c := meta.FindStatusCondition(get(nn).Status.Conditions, t)
		Expect(c).NotTo(BeNil(), "condition %s", t)
		Expect(c.Status).To(Equal(s), "condition %s: %s", t, c.Message)
		Expect(c.Reason).To(Equal(reason))
	}

	// object makes a CloudFirewall that reconciles only the given rule.
	object := func(name, importID string) *alpha1v1.CloudFirewall {
		defaults := false
		return &alpha1v1.CloudFirewall{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: alpha1v1.CloudFirewallSpec{
				ImportID:     importID,
				DefaultRules: &defaults,
				Ruleset: alpha1v1.RulesetSpec{Inbound: []alpha1v1.RuleSpec{{
					Label:     "allow-https",
					Action:    "ACCEPT",
					Protocol:  "TCP",
					Ports:     "443",
					Addresses: alpha1v1.AddressSpec{IPv4: &[]string{"203.0.113.0/24"}},
				}}},
			},
		}
	}
	create := func(name, importID string) types.NamespacedName {
		Expect(kc().Create(ctx, object(name, importID))).To(Succeed())
		return types.NamespacedName{Name: name, Namespace: ns}
	}
	// withStatus points an object at a firewall, as an earlier controller would have.
	withStatus := func(nn types.NamespacedName, id string, nodes ...int) {
		cf := get(nn)
		cf.Status.ID = id
		cf.Status.Nodes = nodes
		Expect(kc().Status().Update(ctx, cf)).To(Succeed())
	}

	// adopt runs the two reconciles that adopt firewall id and apply its rules.
	adopt := func(nn types.NamespacedName, id string) {
		Expect(reconcileOnce(nn)).To(Succeed())
		cf := get(nn)
		Expect(cf.Status.ID).To(Equal(id))
		Expect(cf.Annotations).To(HaveKeyWithValue(alpha1v1.ImportedAnnotation, id))
		expectCondition(nn, alpha1v1.ConditionImported, metav1.ConditionTrue, "Adopted")
		Expect(reconcileOnce(nn)).To(Succeed())
		Expect(api.count("PUT /v4/networking/firewalls/" + id + "/rules")).To(BeNumerically(">=", 1))
		// Nothing to clean up for an adopted firewall, so no finalizer to get stuck.
		Expect(get(nn).Finalizers).To(BeEmpty())
	}

	// deleteAndReconcile deletes the object and runs its finalizer, if any.
	deleteAndReconcile := func(nn types.NamespacedName) {
		Expect(kc().Delete(ctx, get(nn))).To(Succeed())
		if err := kc().Get(ctx, nn, &alpha1v1.CloudFirewall{}); err == nil {
			Expect(reconcileOnce(nn)).To(Succeed())
		}
		Expect(errors.IsNotFound(kc().Get(ctx, nn, &alpha1v1.CloudFirewall{}))).To(BeTrue())
	}

	BeforeEach(func() {
		cleanup = nil
		api = &fakeLinodeAPI{firewalls: map[string]*fakeFirewall{}, instances: map[int]int{
			clusterNode: 123, // this cluster's node
			333:         123, // in this LKE cluster, not registered as a Node yet
			222:         456, // another cluster's node
		}}
		api.fw("999", poolLabel, linode(clusterNode))               // node-pool firewall on this cluster's node
		api.fw("998", poolLabel, iface(clusterNode))                // the same, attached through a Linode interface
		api.fw("997", poolLabel, linode(clusterNode), linode(333))  // with a node still joining
		api.fw("996", poolLabel)                                    // a pool firewall the nodes cannot be on yet
		api.fw("777", poolLabel, linode(222))                       // another cluster's firewall
		api.fw("666", poolLabel, linode(clusterNode), linode(222))  // shared with another cluster
		api.fw("555", ownedLabel, linode(clusterNode), linode(444)) // a firewall the controller created
		srv := httptest.NewServer(api)
		DeferCleanup(srv.Close)
		GinkgoT().Setenv("LINODE_URL", srv.URL)

		reconciler = &CloudFirewallReconciler{
			Client:    kc(),
			Scheme:    kc().Scheme(),
			ClusterID: clusterID,
			lApiOpts:  internal.LinodeApiOptions{Credentials: credName, CredentialsNs: ns},
		}

		if err := kc().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil &&
			!errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		ensure(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: credName, Namespace: ns},
			Data:       map[string][]byte{"token": []byte("test-token")},
		})
		// checkOwnership sets the controller Deployment as owner.
		labels := map[string]string{"app": "cloud-firewall-controller"}
		ensure(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "cloud-firewall-controller", Namespace: ns},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "i"}}},
				},
			},
		})
		// The cluster's node. It is not in any object's status, so an owned
		// firewall would try to attach it; an imported one must not.
		ensure(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "lke123-1-abcdef"},
			Spec:       corev1.NodeSpec{ProviderID: fmt.Sprintf("linode://%d", clusterNode)},
		})
	})

	AfterEach(func() {
		for _, obj := range cleanup {
			Expect(client.IgnoreNotFound(kc().Delete(ctx, obj))).To(Succeed())
		}
		// Remove every CloudFirewall, including ones a failed spec left behind with
		// a finalizer, so each spec starts from an empty namespace.
		list := &alpha1v1.CloudFirewallList{}
		Expect(kc().List(ctx, list)).To(Succeed())
		for i := range list.Items {
			cf := &list.Items[i]
			if len(cf.Finalizers) > 0 {
				cf.Finalizers = nil
				Expect(client.IgnoreNotFound(kc().Update(ctx, cf))).To(Succeed())
			}
			Expect(client.IgnoreNotFound(kc().Delete(ctx, cf))).To(Succeed())
		}
	})

	It("adopts the firewall, applies rules once, and never creates, attaches, or deletes", func() {
		nn := create("imported", "999")
		adopt(nn, "999")
		expectCondition(nn, alpha1v1.ConditionNodesProtected, metav1.ConditionTrue, "AllNodesAttached")

		By("not re-applying rules that already match")
		Expect(reconcileOnce(nn)).To(Succeed())
		Expect(api.count("PUT /v4/networking/firewalls/999/rules")).To(Equal(1))

		By("leaving the firewall in place when the object is deleted")
		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("999"))
		Expect(api.mutating()).To(BeEmpty())
	})

	It("adopts a firewall attached to the nodes through Linode interfaces", func() {
		nn := create("imported-iface", "998")
		adopt(nn, "998")
		deleteAndReconcile(nn)
		Expect(api.mutating()).To(BeEmpty())
	})

	It("adopts a firewall attached to a cluster Linode that is not a Node yet", func() {
		nn := create("imported-joining", "997")
		adopt(nn, "997")
		deleteAndReconcile(nn)
		Expect(api.mutating()).To(BeEmpty())
	})

	It("reports nodes the imported firewall does not protect", func() {
		nn := create("imported-empty", "996")
		adopt(nn, "996")
		expectCondition(nn, alpha1v1.ConditionNodesProtected, metav1.ConditionFalse, "NodesNotAttached")
		deleteAndReconcile(nn)
		Expect(api.mutating()).To(BeEmpty())
	})

	It("does not recreate an imported firewall that no longer exists", func() {
		nn := create("imported-missing", "404")
		Expect(reconcileOnce(nn)).NotTo(Succeed())
		Expect(get(nn).Status.ID).To(BeEmpty())
		expectCondition(nn, alpha1v1.ConditionImported, metav1.ConditionFalse, "ImportRefused")
		Expect(api.mutating()).To(BeEmpty())
		deleteAndReconcile(nn)
	})

	It("refuses a firewall attached only to devices outside the cluster", func() {
		nn := create("imported-foreign", "777")
		Expect(reconcileOnce(nn)).To(MatchError(ContainSubstring("not nodes of this cluster [linode:222]")))
		Expect(get(nn).Status.ID).To(BeEmpty())
		expectCondition(nn, alpha1v1.ConditionImported, metav1.ConditionFalse, "ImportRefused")
		Expect(api.count("PUT /v4/networking/firewalls/777/rules")).To(BeZero())
		Expect(api.mutating()).To(BeEmpty())
		deleteAndReconcile(nn)
	})

	It("refuses a firewall shared between this cluster and other devices", func() {
		nn := create("imported-shared", "666")
		Expect(reconcileOnce(nn)).To(MatchError(ContainSubstring("not nodes of this cluster [linode:222]")))
		Expect(get(nn).Status.ID).To(BeEmpty())
		Expect(api.count("PUT /v4/networking/firewalls/666/rules")).To(BeZero())
		Expect(api.mutating()).To(BeEmpty())
		deleteAndReconcile(nn)
	})

	It("releases, and never deletes, an adopted firewall when firewall-id is removed", func() {
		nn := create("imported-released", "999")
		adopt(nn, "999")

		By("removing firewall-id")
		cf := get(nn)
		cf.Spec.ImportID = ""
		Expect(kc().Update(ctx, cf)).To(Succeed())
		Expect(reconcileOnce(nn)).To(Succeed())
		cf = get(nn)
		Expect(cf.Status.ID).To(BeEmpty())
		Expect(cf.Annotations).NotTo(HaveKey(alpha1v1.ImportedAnnotation))

		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("999"))
		Expect(api.mutating()).To(BeEmpty())
	})

	It("never deletes an adopted firewall even if its status is lost", func() {
		nn := create("imported-status-lost", "999")
		adopt(nn, "999")

		By("losing every status field but the ID, then removing firewall-id")
		cf := get(nn)
		cf.Status = alpha1v1.CloudFirewallStatus{ID: "999"}
		Expect(kc().Status().Update(ctx, cf)).To(Succeed())
		cf = get(nn)
		cf.Spec.ImportID = ""
		Expect(kc().Update(ctx, cf)).To(Succeed())
		Expect(reconcileOnce(nn)).To(Succeed())

		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("999"))
		Expect(api.mutating()).To(BeEmpty())
	})

	It("never deletes an adopted firewall when the annotation is lost and firewall-id changes", func() {
		nn := create("imported-replaced", "999")
		adopt(nn, "999")

		By("re-applying the object with another firewall-id and no annotation, as kubectl replace would")
		cf := get(nn)
		delete(cf.Annotations, alpha1v1.ImportedAnnotation)
		cf.Spec.ImportID = "998"
		Expect(kc().Update(ctx, cf)).To(Succeed())
		adopt(nn, "998")

		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("999"))
		Expect(api.firewalls).To(HaveKey("998"))
		Expect(api.mutating()).To(BeEmpty())
	})

	It("moves the nodes onto the imported firewall before deleting its own", func() {
		nn := create("switched", "")
		withStatus(nn, "555", clusterNode, 444)
		nodeDevice := api.firewalls["555"].devices[0].id // clusterNode's device on 555

		cf := get(nn)
		cf.Spec.ImportID = "996"
		Expect(kc().Update(ctx, cf)).To(Succeed())
		adopt(nn, "996")

		Expect(api.firewalls).NotTo(HaveKey("555"))
		Expect(api.linodesOn("996")).To(Equal([]int{clusterNode}))
		Expect(api.mutating()).To(Equal([]string{
			"DELETE /v4/networking/firewalls/555/devices/" + strconv.Itoa(nodeDevice),
			"POST /v4/networking/firewalls/996/devices",
			"DELETE /v4/networking/firewalls/555",
		}))
		Expect(api.requests).To(ContainElement("PUT /v4/networking/firewalls/996/rules"))
		Expect(indexOf(api.requests, "PUT /v4/networking/firewalls/996/rules")).
			To(BeNumerically("<", indexOf(api.requests, "POST /v4/networking/firewalls/996/devices")),
				"rules must be on the imported firewall before nodes move onto it")

		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("996"))
	})

	It("does not delete the previously adopted firewall when switched to another", func() {
		nn := create("reimported", "999")
		adopt(nn, "999")
		cf := get(nn)
		cf.Spec.ImportID = "998"
		Expect(kc().Update(ctx, cf)).To(Succeed())
		adopt(nn, "998")

		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("999"))
		Expect(api.firewalls).To(HaveKey("998"))
		Expect(api.mutating()).To(BeEmpty())
	})

	It("detaches a removed node from its own firewall by device ID, and deletes it with the object", func() {
		nn := create("owned", "")
		withStatus(nn, "555", clusterNode, 444)
		Expect(reconcileOnce(nn)).To(Succeed())

		Expect(get(nn).Status.Nodes).To(Equal([]int{clusterNode}))
		Expect(api.linodesOn("555")).To(Equal([]int{clusterNode}))
		Expect(get(nn).Finalizers).To(ContainElement(finalizerName))

		deleteAndReconcile(nn)
		Expect(api.firewalls).NotTo(HaveKey("555"))
	})

	It("leaves a firewall it did not create alone even without an import marker", func() {
		nn := create("hand-pointed", "")
		withStatus(nn, "999")
		Expect(reconcileOnce(nn)).To(Succeed())
		Expect(get(nn).Finalizers).To(BeEmpty())

		deleteAndReconcile(nn)
		Expect(api.firewalls).To(HaveKey("999"))
		Expect(api.mutating()).To(BeEmpty())
	})

	It("does not auto-create a default object when that is disabled", func() {
		list := &alpha1v1.CloudFirewallList{}
		Expect(kc().List(ctx, list)).To(Succeed())
		Expect(list.Items).To(BeEmpty())

		reconciler.mapNodeEvent(ctx, kc(), &corev1.Node{})
		Expect(kc().List(ctx, list)).To(Succeed())
		Expect(list.Items).To(BeEmpty())

		reconciler.AutoCreateDefault = true
		reconciler.mapNodeEvent(ctx, kc(), &corev1.Node{})
		Expect(kc().List(ctx, list)).To(Succeed())
		Expect(list.Items).To(HaveLen(1))
		Expect(kc().Delete(ctx, &list.Items[0])).To(Succeed())
	})

	if strictCRD {
		It("rejects a non-numeric firewall-id at admission", func() {
			err := kc().Create(ctx, object("imported-bad-id", "fw-123"))
			Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
		})
	}

	It("requires defaultRules to be set explicitly in import mode", func() {
		cf := object("imported-no-defaults", "999")
		cf.Spec.DefaultRules = nil
		err := kc().Create(ctx, cf)
		if strictCRD {
			Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
			return
		}
		Expect(err).NotTo(HaveOccurred())
		// The older CRD defaults defaultRules to true at admission, so "unset"
		// cannot reach the controller there; only the current CRD (and the chart)
		// can require an explicit choice. Record that this is the case.
		nn := types.NamespacedName{Name: cf.Name, Namespace: ns}
		Expect(get(nn).Spec.DefaultRules).To(HaveValue(BeTrue()))
		Expect(kc().Delete(ctx, get(nn))).To(Succeed())
	})

	It("requires inbound rules when importing with defaultRules false", func() {
		cf := object("imported-no-rules", "999")
		cf.Spec.Ruleset = alpha1v1.RulesetSpec{}
		err := kc().Create(ctx, cf)
		if strictCRD {
			Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
			return
		}
		Expect(err).NotTo(HaveOccurred())
		nn := types.NamespacedName{Name: cf.Name, Namespace: ns}
		Expect(reconcileOnce(nn)).To(MatchError(ContainSubstring("ruleset.inbound must list")))
		Expect(api.count("PUT /v4/networking/firewalls/999/rules")).To(BeZero())
		deleteAndReconcile(nn)
	})
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}
