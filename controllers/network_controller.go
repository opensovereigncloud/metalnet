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

	networkingv1alpha1 "github.com/onmetal/metalnet/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	NetworkFinalizerName = "networking.metalnet.onmetal.de/network"
	networkRefField      = ".spec.networkRef.name"
)

// NetworkReconciler reconciles a Network object
type NetworkReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	HostName string
}

//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networks,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networks/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networks/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkinterfaces,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	network := &networkingv1alpha1.Network{}

	if err := r.Get(ctx, req.NamespacedName, network); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// refNetworkInterfaces := &networkingv1alpha1.NetworkInterfaceList{}
	// listOps := &client.ListOptions{
	// 	FieldSelector: fields.OneTermEqualSelector(networkRefField, req.Name),
	// 	Namespace:     req.Namespace,
	// }
	// err := r.List(ctx, refNetworkInterfaces, listOps)
	// if err != nil {
	// 	return ctrl.Result{}, err
	// }

	changeFinalizerFunc := controllerutil.AddFinalizer
	// if !network.DeletionTimestamp.IsZero() && len(refNetworkInterfaces.Items) == 0 {
	// 	changeFinalizerFunc = controllerutil.RemoveFinalizer
	// }

	clone := network.DeepCopy()
	if !changeFinalizerFunc(clone, NetworkFinalizerName) {
		return ctrl.Result{}, nil
	}

	if err := r.Patch(ctx, clone, client.MergeFrom(network)); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkingv1alpha1.NetworkInterface{}, networkRefField, func(rawObj client.Object) []string {
	// 	ni := rawObj.(*networkingv1alpha1.NetworkInterface)
	// 	return []string{ni.Spec.NetworkRef.Name}
	// }); err != nil {
	// 	return err
	// }

	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.Network{}).
		WithEventFilter(predicate.ResourceVersionChangedPredicate{}).
		// Watches(
		// 	&source.Kind{Type: &networkingv1alpha1.NetworkInterface{}},
		// 	handler.EnqueueRequestsFromMapFunc(r.findObjectsForNetworkInterface),
		// 	builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		// ).
		Complete(r)
}

// func (r *NetworkReconciler) findObjectsForNetworkInterface(obj client.Object) []reconcile.Request {
// 	networkInterface, ok := obj.(*networkingv1alpha1.NetworkInterface)
// 	if !ok {
// 		return []reconcile.Request{}
// 	}

// 	return []reconcile.Request{{
// 		NamespacedName: types.NamespacedName{
// 			Name:      networkInterface.Spec.NetworkRef.Name,
// 			Namespace: networkInterface.GetNamespace(),
// 		},
// 	}}
// }
