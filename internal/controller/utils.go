package controller

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	internal "bits.linode.com/hwagner/cloud-firewall-controller/internal/types"
	lgo "github.com/linode/linodego"
	"golang.org/x/oauth2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type FirewallObject interface {
	client.Object
	GetID() (int, error)
	Exists() bool
	GetStatusID() string
}

// FirewallReconciler provides an interface for reconciler operations
type FirewallReconciler interface {
	client.Reader
	client.Writer
	client.StatusClient
	GetLClient() lgo.Client
	deleteExternalResources(ctx context.Context, obj FirewallObject) error
}

// checkOwnership is a generic function for setting controller ownership on a FirewallObject
func checkOwnership[T FirewallObject](ctx context.Context, r client.Reader, obj T, scheme *runtime.Scheme) error {
	owner := metav1.GetControllerOf(obj)
	if owner != nil {
		return nil
	}

	// Fetch the controller deployment
	ctrlDpl := appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      "cloud-firewall-controller",
		Namespace: "kube-system",
	}, &ctrlDpl)
	if err != nil {
		return fmt.Errorf("failed to get controller deployment: %s", err.Error())
	}

	klog.Infof("[%s/%s] set controller reference controller=(%s/%s)", obj.GetNamespace(), obj.GetName(), ctrlDpl.Namespace, ctrlDpl.Name)

	if err = ctrl.SetControllerReference(&ctrlDpl, obj, scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %s", err.Error())
	}

	return nil
}

// checkFinalizer is a generic function for handling finalizers on a FirewallObject
func checkFinalizer[T FirewallObject](ctx context.Context, r FirewallReconciler, obj T, kind string) (bool, error) {
	finalizerName := fmt.Sprintf("%s.networking.linode.com/finalizer", kind)
	deleted := false

	if obj.GetDeletionTimestamp().IsZero() {
		klog.Infof("[%s/%s] adding finalizer finalizer=(%s)", obj.GetNamespace(), obj.GetName(), finalizerName)
		if !controllerutil.ContainsFinalizer(obj, finalizerName) {
			controllerutil.AddFinalizer(obj, finalizerName)
			return deleted, nil
		}
	} else {
		if controllerutil.ContainsFinalizer(obj, finalizerName) {
			// Handle firewall deletion
			if err := r.deleteExternalResources(context.WithoutCancel(ctx), obj); err != nil {
				if !FirewallIsNotFound(err) {
					return deleted, err
				}
			}

			klog.Infof("[%s/%s] firewall deleted", obj.GetNamespace(), obj.GetName())
			deleted = true

			// Remove the finalizer and update the object
			if controllerutil.RemoveFinalizer(obj, finalizerName) {
				if err := r.Update(context.WithoutCancel(ctx), obj); err != nil {
					klog.Infof("[%s/%s] failed to update finalizer - %s", obj.GetNamespace(), obj.GetName(), err.Error())
				}
			} else {
				klog.Infof("[%s/%s] failed to remove finalizer", obj.GetNamespace(), obj.GetName())
			}
		} else {
			klog.Infof("[%s/%s] deletion called with no finalizer found", obj.GetNamespace(), obj.GetName())
		}
	}

	return deleted, nil
}

func createLinodeClient(r LinodeClientSetter, opts internal.LinodeApiOptions) error {
	creds := &corev1.Secret{}
	err := r.Get(context.TODO(), client.ObjectKey{
		Name:      opts.Credentials,
		Namespace: opts.CredentialsNs,
	}, creds)
	if err != nil {
		return fmt.Errorf("failed to get API credentials: %s", err.Error())
	}

	apiKey := creds.Data["token"]
	if len(apiKey) == 0 {
		return fmt.Errorf("failed to parse Linode API token")
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: string(apiKey)})
	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	lcli := lgo.NewClient(oauth2Client)
	lcli.SetUserAgent(fmt.Sprintf("cloud-firewall-controller %s", lgo.DefaultUserAgent))
	lcli.SetDebug(opts.Debug)

	r.SetLinodeClient(&lcli)
	return nil
}

func deleteExternalResources[T FirewallObject](ctx context.Context, r FirewallReconciler, obj T) error {
	klog.Infof("[%s/%s] deleting firewall (%s)", obj.GetNamespace(), obj.GetName(), obj.GetStatusID())

	objID, err := obj.GetID()
	if err != nil {
		return fmt.Errorf("failed to get firewall ID - %s", err.Error())
	}
	lcli := r.GetLClient()
	return lcli.DeleteFirewall(ctx, objID)
}

func addDevices(ctx context.Context, r FirewallReconciler, devices []int, firewallID int, deviceType lgo.FirewallDeviceType, deviceList *[]int) error {
	for _, device := range devices {
		opts := lgo.FirewallDeviceCreateOptions{
			ID:   device,
			Type: deviceType,
		}
		lcli := r.GetLClient()
		if _, err := lcli.CreateFirewallDevice(ctx, firewallID, opts); err != nil {
			return fmt.Errorf("failed to add device (%d - %s) to firewall (%d)", device, deviceType, firewallID)
		}
		// Append device to status list
		*deviceList = append(*deviceList, device)
	}
	return nil
}

func removeDevices(ctx context.Context, r FirewallReconciler, devices []int, firewallID int, deviceList *[]int) error {
	for _, device := range devices {
		lcli := r.GetLClient()
		if err := lcli.DeleteFirewallDevice(ctx, firewallID, device); err != nil {
			return fmt.Errorf("failed to remove device (%d) from firewall (%d) - %s", device, firewallID, err.Error())
		}
		// Remove the device from status list
		*deviceList = removeItem(*deviceList, device)
	}
	return nil
}

func removeItems[T comparable](s *[]T, itemsToRemove []T) {
	for _, item := range itemsToRemove {
		*s = removeItem(*s, item)
	}
}

func removeItem[T comparable](s []T, item T) []T {
	index := slices.Index(s, item)
	klog.Infof("removeItem: removing=%v, from slice=%v, index=%d", item, s, index)
	if index == -1 {
		return s // Item not found, return original slice
	}
	return slices.Delete(s, index, index+1)
}
