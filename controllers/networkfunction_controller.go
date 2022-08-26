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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
	"github.com/onmetal/controller-utils/clientutils"
	networkingv1alpha1 "github.com/onmetal/metalnet/api/v1alpha1"
)

const finalizer = "networking.metalnet.onmetal.de/function"

// NetworkFunctionReconciler reconciles a NetworkFunction object
type NetworkFunctionReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Hostname        string
	DeviceAllocator DeviceAllocator
}

//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkfunctions,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkfunctions/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkfunctions/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NetworkFunction object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *NetworkFunctionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	function := &networkingv1alpha1.NetworkFunction{}
	if err := r.Get(ctx, req.NamespacedName, function); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return r.reconcileExists(ctx, log, function)
}

func (r *NetworkFunctionReconciler) reconcileExists(ctx context.Context, log logr.Logger, function *networkingv1alpha1.NetworkFunction) (ctrl.Result, error) {
	if !function.DeletionTimestamp.IsZero() {
		return r.delete(ctx, log, function)
	}
	return r.reconcile(ctx, log, function)
}

func (r *NetworkFunctionReconciler) delete(ctx context.Context, log logr.Logger, function *networkingv1alpha1.NetworkFunction) (ctrl.Result, error) {
	if err := clientutils.PatchRemoveFinalizer(ctx, r.Client, function, finalizer); err != nil {
		return ctrl.Result{}, err
	}
	if function.Status.PCIAddress != "" {
		log.V(1).Info("Freeing the Network Function", "PCI:", function.Status.PCIAddress)
		r.DeviceAllocator.FreeDevice(function.Status.PCIAddress)
	}
	return ctrl.Result{}, nil
}

func (r *NetworkFunctionReconciler) reconcile(ctx context.Context, log logr.Logger, function *networkingv1alpha1.NetworkFunction) (ctrl.Result, error) {
	log.V(1).Info("Reconcile")

	log.V(1).Info("Ensuring finalizer")
	if modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, function, finalizer); err != nil || modified {
		return ctrl.Result{Requeue: true}, err
	}

	if function.Spec.TargetRef != nil {
		return r.reconcileBound(ctx, log, function)
	}
	return r.reconcileUnbound(ctx, log, function)
}

func (r *NetworkFunctionReconciler) reconcileBound(ctx context.Context, log logr.Logger, function *networkingv1alpha1.NetworkFunction) (ctrl.Result, error) {

	if function.Spec.NodeName == nil {
		log.V(1).Info("Network Function is not yet assigned to a node.")
		return ctrl.Result{Requeue: true}, nil
	}
	if function.Status.PCIAddress != "" {
		r.DeviceAllocator.ReserveDeviceWithName(function.Status.PCIAddress)
	} else {
		newDevice, err := r.DeviceAllocator.ReserveDevice()
		if err != nil {
			log.V(1).Error(err, "Network function error")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Assigning new Network Function", "PCI:", newDevice)
		if err := r.patchStatus(ctx, function, networkingv1alpha1.NetworkFunctionBound, newDevice); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func (r *NetworkFunctionReconciler) reconcileUnbound(ctx context.Context, log logr.Logger, function *networkingv1alpha1.NetworkFunction) (ctrl.Result, error) {
	log.V(1).Info("Running Unbound")
	if function.Status.PCIAddress == "" {
		if err := r.patchStatus(ctx, function, networkingv1alpha1.NetworkFunctionUnbound, ""); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func (r *NetworkFunctionReconciler) patchStatus(ctx context.Context, function *networkingv1alpha1.NetworkFunction, phase networkingv1alpha1.NetworkFunctionPhase, pciID string) error {
	base := function.DeepCopy()
	now := metav1.Now()
	if function.Status.Phase != phase {
		function.Status.LastPhaseTransitionTime = &now
	}
	function.Status.Phase = phase
	function.Status.PCIAddress = pciID
	return r.Status().Patch(ctx, function, client.MergeFrom(base))
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkFunctionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.NetworkFunction{}).
		Complete(r)
}
