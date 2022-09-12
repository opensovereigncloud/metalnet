/*
Copyright 2022 The Metal Authors.

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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	"github.com/onmetal/controller-utils/clientutils"
	mb "github.com/onmetal/metalbond"
	"github.com/onmetal/metalnet/api/v1alpha1"
	networkingv1alpha1 "github.com/onmetal/metalnet/api/v1alpha1"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
)

const aliasPrefixFinalizer = "networking.metalnet.onmetal.de/aliasprefix"

// AliasPrefixReconciler reconciles a AliasPrefix object
type AliasPrefixReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	DPDKClient dpdkproto.DPDKonmetalClient
	MbInstance *mb.MetalBond
	HostName   string
}

//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=aliasprefixes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=aliasprefixes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=aliasprefixes/finalizers,verbs=update

//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkinterfaces,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkinterfaces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AliasPrefixReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	aliasPrefix := &networkingv1alpha1.AliasPrefix{}
	if err := r.Get(ctx, req.NamespacedName, aliasPrefix); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return r.reconcileExists(ctx, log, aliasPrefix)
}

func (r *AliasPrefixReconciler) reconcileExists(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix) (ctrl.Result, error) {
	if !aliasPrefix.DeletionTimestamp.IsZero() {
		return r.delete(ctx, log, aliasPrefix)
	}
	return r.reconcile(ctx, log, aliasPrefix)
}

func (r *AliasPrefixReconciler) delete(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix) (ctrl.Result, error) {
	log.V(1).Info("Deleting AliasPrefix flow")

	niList, err := r.getRelatedNetworkInterfaces(ctx, aliasPrefix)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(niList) > 1 {
		return ctrl.Result{}, fmt.Errorf("only one related NetworkInterface is supporting now")
	}

	if err := r.deletePrefixForNI(ctx, log, aliasPrefix, niList, true); err != nil {
		return ctrl.Result{}, err
	}
	for _, ni := range niList {
		n := &networkingv1alpha1.Network{}
		key := types.NamespacedName{
			Namespace: aliasPrefix.Namespace,
			Name:      ni.Spec.NetworkRef.Name,
		}
		if err := r.Get(ctx, key, n); err != nil {
			log.Info("unable to fetch Network", "Error", err)
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if err := r.announcePrefix(ctx, log, aliasPrefix, aliasPrefix.Status.UnderlayIP.String(), n.Spec.ID, ROUTEREMOVE); err != nil {
			return ctrl.Result{}, err
		}
		if err := clientutils.PatchRemoveFinalizer(ctx, r.Client, &ni, aliasPrefixFinalizer); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	if err := clientutils.PatchRemoveFinalizer(ctx, r.Client, aliasPrefix, aliasPrefixFinalizer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, nil
}

func (r *AliasPrefixReconciler) reconcile(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix) (ctrl.Result, error) {
	log.V(1).Info("Reconciling AliasPrefix")

	if _, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, aliasPrefix, aliasPrefixFinalizer); err != nil {
		return ctrl.Result{}, err
	}

	niList, err := r.getRelatedNetworkInterfaces(ctx, aliasPrefix)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(niList) > 1 {
		return ctrl.Result{}, fmt.Errorf("only one related NetworkInterface is supported now")
	}

	if err := r.addPrefixes(ctx, log, aliasPrefix, niList); err != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return ctrl.Result{}, nil

}

func (r *AliasPrefixReconciler) getRelatedNetworkInterfaces(ctx context.Context, aliasPrefix *networkingv1alpha1.AliasPrefix) ([]networkingv1alpha1.NetworkInterface, error) {
	niList := &networkingv1alpha1.NetworkInterfaceList{}

	var labelSelector labels.Selector
	labelSelector, err := metav1.LabelSelectorAsSelector(aliasPrefix.Spec.NetworkInterfaceSelector)
	if err != nil {
		return nil, err
	}

	listOptions := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(networkRefField, aliasPrefix.Spec.NetworkRef.Name),
		LabelSelector: labelSelector,
	}
	if err := r.List(ctx, niList, listOptions, client.MatchingFields{nodeNameField: r.HostName}); err != nil {
		return nil, err
	}
	return niList.Items, nil
}

func (r *AliasPrefixReconciler) addPrefixes(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix, niList []networkingv1alpha1.NetworkInterface) error {
	if aliasPrefix.Spec.Prefix.Value == nil {
		log.Info("IP prefix is nil. AliasPrefix will be skipped.", "aliasPrefix", aliasPrefix.GetName())
		return nil
	}
	if len(niList) == 0 {
		return errors.New("no matching NetworkInterface")
	}
	for _, ni := range niList {
		if !ni.DeletionTimestamp.IsZero() {
			continue
		}
		if ni.Status.Access == nil {
			continue
		}
		log = log.WithValues("NetworkInterface", ni.GetName())
		machineID := &dpdkproto.InterfaceIDMsg{
			InterfaceID: []byte(ni.Status.Access.UID),
		}

		prefix := &dpdkproto.Prefix{}
		if aliasPrefix.Spec.Prefix.Value.IPPrefix.IP().Is4() {
			prefix.IpVersion = dpdkproto.IPVersion_IPv4
		} else {
			prefix.IpVersion = dpdkproto.IPVersion_IPv6
		}
		prefix.Address = []byte(aliasPrefix.Spec.Prefix.Value.IPPrefix.IP().String())
		prefix.PrefixLength = uint32(aliasPrefix.Spec.Prefix.Value.IPPrefix.Bits())

		n := &networkingv1alpha1.Network{}
		key := types.NamespacedName{
			Namespace: aliasPrefix.Namespace,
			Name:      ni.Spec.NetworkRef.Name,
		}
		if err := r.Get(ctx, key, n); err != nil {
			log.Info("unable to fetch Network", "Error", err)
			return client.IgnoreNotFound(err)
		}

		if aliasPrefix.Status.Prefix != nil {
			log.Info("test 1")
			if r.prefixExists(ctx, log, aliasPrefix, ni) {
				log.Info("test 2")
				isAnnounced, err := r.isPrefixAnnounced(ctx, log, aliasPrefix, aliasPrefix.Status.UnderlayIP.String(), n.Spec.ID)
				log.Info("test 3")
				if err == nil && !isAnnounced {
					log.Info("test 4")
					if err := r.announcePrefix(ctx, log, aliasPrefix, aliasPrefix.Status.UnderlayIP.String(), n.Spec.ID, ROUTEADD); err != nil {
						return err
					}
				}
				continue
			}
		}

		reg := &dpdkproto.InterfacePrefixMsg{
			InterfaceID: machineID,
			Prefix:      prefix,
		}
		status, err := r.DPDKClient.AddInterfacePrefix(ctx, reg)
		log.Info("test 5", "error code", status.Status.Error)
		if err != nil {
			log.Info("test 6")
			return err
		}
		if status.Status.Error != dpdkExitSuccess {
			return fmt.Errorf("error during AddInterfacePrefix call: Error code - %v", status.Status.Error)
		}
		log.Info("test 7")
		if err := r.announcePrefix(ctx, log, aliasPrefix, string(status.UnderlayRoute), n.Spec.ID, ROUTEADD); err != nil {
			return err
		}

		if err := clientutils.PatchAddFinalizer(ctx, r.Client, &ni, aliasPrefixFinalizer); err != nil {
			return err
		}
		clone := aliasPrefix.DeepCopy()
		clone.Status.Prefix = aliasPrefix.Spec.Prefix.Value
		clone.Status.UnderlayIP = v1alpha1.MustParseNewIP(string(status.UnderlayRoute))

		if err := r.Status().Patch(ctx, clone, client.MergeFrom(aliasPrefix)); err != nil {
			log.Info("unable to update AliasPrefix", "AliasPrefix", aliasPrefix, "Error", err)
			return client.IgnoreNotFound(err)
		}
	}
	return nil
}

func (r *AliasPrefixReconciler) prefixExists(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix, ni networkingv1alpha1.NetworkInterface) bool {
	machineID := &dpdkproto.InterfaceIDMsg{
		InterfaceID: []byte(ni.Status.Access.UID),
	}

	prefix := &dpdkproto.Prefix{}
	if aliasPrefix.Spec.Prefix.Value.IPPrefix.IP().Is4() {
		prefix.IpVersion = dpdkproto.IPVersion_IPv4
	} else {
		prefix.IpVersion = dpdkproto.IPVersion_IPv6
	}
	prefix.Address = []byte(aliasPrefix.Spec.Prefix.Value.IPPrefix.IP().String())
	prefix.PrefixLength = uint32(aliasPrefix.Spec.Prefix.Value.IPPrefix.Bits())

	prefixMsg, err := r.DPDKClient.ListInterfacePrefixes(ctx, machineID)
	if err != nil {
		return false
	}
	if len(prefixMsg.Prefixes) == 0 {
		return false
	}
	isPresent := true
	for _, p := range prefixMsg.Prefixes {
		isPresent = true
		isPresent = (isPresent && (p.IpVersion == prefix.IpVersion))
		isPresent = (isPresent && (string(p.Address) == string(prefix.Address)))
		isPresent = (isPresent && (p.PrefixLength == prefix.PrefixLength))
		if isPresent {
			break
		}
	}
	return isPresent
}

func (r *AliasPrefixReconciler) deletePrefixForNI(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix, niList []networkingv1alpha1.NetworkInterface, deleteAll bool) error {
	if aliasPrefix.Spec.Prefix.Value == nil {
		log.Info("IP prefix is nil. Prefix deletion skipped.", "aliasPrefix", aliasPrefix.Name)
		return nil
	}
	log.V(1).Info("Delete alias prefix")
	for _, ni := range niList {
		if ni.DeletionTimestamp.IsZero() && !deleteAll {
			continue
		}
		if ni.Status.Access == nil {
			continue
		}
		prefix := &dpdkproto.Prefix{}
		if aliasPrefix.Spec.Prefix.Value.IPPrefix.IP().Is4() {
			prefix.IpVersion = dpdkproto.IPVersion_IPv4
		} else {
			prefix.IpVersion = dpdkproto.IPVersion_IPv6
		}
		prefix.Address = []byte(aliasPrefix.Spec.Prefix.Value.IPPrefix.IP().String())
		prefix.PrefixLength = uint32(aliasPrefix.Spec.Prefix.Value.IPPrefix.Bits())

		reg := &dpdkproto.InterfacePrefixMsg{
			InterfaceID: &dpdkproto.InterfaceIDMsg{
				InterfaceID: []byte(ni.Status.Access.UID),
			},
			Prefix: prefix,
		}

		if !r.prefixExists(ctx, log, aliasPrefix, ni) {
			continue
		}

		log.V(1).Info("DELETE", "reg", reg)

		status, err := r.DPDKClient.DeleteInterfacePrefix(ctx, reg)
		if err != nil {
			return err
		}
		if status.Error != dpdkExitSuccess && status.Error != dpdkPrefixInterfaceNotFound {
			return fmt.Errorf("eror during DeleteInterfacePrefix call: Error code - %v", status.Error)
		}

		if err := clientutils.PatchRemoveFinalizer(ctx, r.Client, &ni, aliasPrefixFinalizer); err != nil {
			return err
		}

	}
	return nil
}

func (r *AliasPrefixReconciler) isPrefixAnnounced(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix, ulRoute string, nID int32) (bool, error) {
	ip := aliasPrefix.Spec.Prefix.Value.String()
	hop, dest, err := prepareMbParameters(ctx, ip, ulRoute)
	if err != nil {
		return false, err
	}

	if r.MbInstance.IsRouteAnnounced(mb.VNI(nID), *dest, *hop) {
		return true, nil
	}
	return false, nil
}

func (r *AliasPrefixReconciler) announcePrefix(ctx context.Context, log logr.Logger, aliasPrefix *networkingv1alpha1.AliasPrefix, ulRoute string, nID int32, action int) error {
	ip := aliasPrefix.Spec.Prefix.Value.String()
	hop, dest, err := prepareMbParameters(ctx, ip, ulRoute)
	if err != nil {
		return err
	}

	if action == ROUTEADD {
		if err = r.MbInstance.AnnounceRoute(mb.VNI(nID), *dest, *hop); err != nil {
			return fmt.Errorf("failed to announce a local route, reason: %v", err)
		}
	} else {
		log.V(1).Info("Deleting AliasPrefix flow 6")
		if err = r.MbInstance.WithdrawRoute(mb.VNI(nID), *dest, *hop); err != nil {
			return fmt.Errorf("failed to withdraw a local route, reason: %v", err)
		}
	}

	return nil
}

const (
	networkReferenceField = ".spec.networkRef.name"
	nodeNameField         = ".spec.nodeName"
)

// SetupWithManager sets up the controller with the Manager.
func (r *AliasPrefixReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkingv1alpha1.NetworkInterface{}, nodeNameField, func(rawObj client.Object) []string {
		ni := rawObj.(*networkingv1alpha1.NetworkInterface)
		if ni.Spec.NodeName != nil {
			return []string{*ni.Spec.NodeName}
		}
		return []string{}
	}); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkingv1alpha1.AliasPrefix{}, networkReferenceField, func(rawObj client.Object) []string {
		ni := rawObj.(*networkingv1alpha1.AliasPrefix)
		return []string{ni.Spec.NetworkRef.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.AliasPrefix{}).
		Watches(
			&source.Kind{Type: &networkingv1alpha1.NetworkInterface{}},
			handler.EnqueueRequestsFromMapFunc(r.findObjectsForAliasPrefix),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}

func (r *AliasPrefixReconciler) findObjectsForAliasPrefix(obj client.Object) []reconcile.Request {
	networkInterface, ok := obj.(*networkingv1alpha1.NetworkInterface)
	if !ok {
		return []reconcile.Request{}
	}
	if networkInterface.Spec.NodeName != nil && *networkInterface.Spec.NodeName != r.HostName {
		return []reconcile.Request{}
	}
	attachedAliasPrefixList := &networkingv1alpha1.AliasPrefixList{}
	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(networkReferenceField, networkInterface.Spec.NetworkRef.Name),
		Namespace:     networkInterface.GetNamespace(),
	}

	err := r.List(context.TODO(), attachedAliasPrefixList, listOps)
	if err != nil {
		return []reconcile.Request{}
	}
	requests := make([]reconcile.Request, len(attachedAliasPrefixList.Items))
	for i, item := range attachedAliasPrefixList.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			},
		}
	}
	return requests
}
