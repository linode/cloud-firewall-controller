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
	"net/http"

	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	alpha1v1 "bits.linode.com/hwagner/cloud-firewall-controller/api/alpha1v1"
	internal "bits.linode.com/hwagner/cloud-firewall-controller/internal/types"
	lgo "github.com/linode/linodego"
)

// CloudFirewallReconciler reconciles a CloudFirewall object
type CloudFirewallReconciler struct {
	client.Client
	lcli   lgo.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.linode.com,resources=cloudfirewalls/finalizers,verbs=update

// Additional required resource permissions
// watch nodes
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// watch and get Linode API token
//+kubebuilder:rbac:groups="",namespace=kube-system,resourceNames=linode,resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CloudFirewall object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *CloudFirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CloudFirewallReconciler) SetupWithManager(mgr ctrl.Manager, opts internal.LinodeApiOptions) error {
	r.createLinodeClient(mgr, opts)
	return ctrl.NewControllerManagedBy(mgr).
		For(&alpha1v1.CloudFirewall{}).
		// Watch for cluster worker node changes to trigger updates to the firewalls
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, node client.Object) []reconcile.Request {
			cfList := &alpha1v1.CloudFirewallList{}
			if err := mgr.GetClient().List(ctx, cfList); err != nil {
				mgr.GetLogger().Error(err, "failed to list CloudFirewalls")
				return nil
			}
			reqs := make([]reconcile.Request, 0, len(cfList.Items))
			for _, item := range cfList.Items {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: item.GetNamespace(),
						Name:      item.GetName(),
					},
				})
			}
			return reqs
		})).
		Complete(r)
}

func (r *CloudFirewallReconciler) createLinodeClient(mgr ctrl.Manager, opts internal.LinodeApiOptions) (lc *lgo.Client, err error) {
	creds := &corev1.Secret{}
	err = mgr.GetClient().Get(context.TODO(), client.ObjectKey{
		Name:      opts.Credentials,
		Namespace: opts.CredentialsNs,
	},
		creds)
	if err != nil {
		klog.Errorf("[%s/%s] failed to get API credentials", opts.Credentials, opts.CredentialsNs)
		return
	}

	apiKey := creds.Data["token"]
	if len(apiKey) == 0 {
		klog.Errorf("[%s/%s] no Linode API token found", opts.Credentials, opts.CredentialsNs)
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
