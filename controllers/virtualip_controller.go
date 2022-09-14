/*
 * Copyright (c) 2021 by the OnMetal authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/go-logr/logr"
	"github.com/onmetal/controller-utils/clientutils"
	mb "github.com/onmetal/metalbond"
	"github.com/onmetal/metalnet/api/v1alpha1"
	networkingv1alpha1 "github.com/onmetal/metalnet/api/v1alpha1"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	virtualIPFinalizer                = "networking.metalnet.onmetal.de/virtualip"
	virtualIPField                    = ".spec.targetRef.name"
	dpdkExitSuccess             int32 = 0
	dpdkInterfaceNotFound       int32 = 450
	dpdkRouteAlreadyExists      int32 = 351
	dpdkPrefixInterfaceNotFound int32 = 701
)

// VirtualIPReconciler reconciles a VirtualIP object
type VirtualIPReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Hostname        string
	DPDKClient      dpdkproto.DPDKonmetalClient
	PublicVNI       int
	MbInstance      *mb.MetalBond
	MetalbondServer string
}

//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=virtualips,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=virtualips/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=virtualips/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VirtualIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	virtualIP := &networkingv1alpha1.VirtualIP{}
	if err := r.Get(ctx, req.NamespacedName, virtualIP); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return r.reconcileExists(ctx, log, virtualIP)
}

func (r *VirtualIPReconciler) reconcileExists(ctx context.Context, log logr.Logger, virtualIP *networkingv1alpha1.VirtualIP) (ctrl.Result, error) {
	if !virtualIP.DeletionTimestamp.IsZero() {
		return r.delete(ctx, log, virtualIP)
	}
	return r.reconcile(ctx, log, virtualIP)
}

func (r *VirtualIPReconciler) delete(ctx context.Context, log logr.Logger, virtualIP *networkingv1alpha1.VirtualIP) (ctrl.Result, error) {
	log.V(1).Info("Deleting VirtualIP")

	if virtualIP.Status.InterfaceID != "" {
		msg := &dpdkproto.InterfaceIDMsg{InterfaceID: []byte(virtualIP.Status.InterfaceID)}
		status, err := r.DPDKClient.DeleteInterfaceVIP(ctx, msg)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to delete the VIP %s for interface %s : %w", client.ObjectKeyFromObject(virtualIP), virtualIP.Status.InterfaceID, err)
		}

		if err := status.Error; err != dpdkExitSuccess && err != dpdkInterfaceNotFound {
			log.V(1).Info("failed to add InterfaceVIP", "Status", status.Error, "Message", status.Message)
			return ctrl.Result{Requeue: true}, nil
		}

		if virtualIP.Status.UnderlayIP != nil {
			// Withdraw VIP from MetalBond
			log.V(1).Info("Withdrawing PublicIP route", "PublicIP", virtualIP.Spec.IP)
			if err := r.announceInterfacePublicVIPRoute(ctx, log, virtualIP, r.PublicVNI, ROUTEREMOVE); err != nil {
				if !strings.Contains(fmt.Sprint(err), "Nexthop does not exist") {
					log.Error(err, "failed to remove route")
					return ctrl.Result{}, err
				} else {
					log.Info("Tried to remove the same route for the same VM.")
				}
				// return ctrl.Result{}, fmt.Errorf("failed to withdraw a route for virtualIP %s:%w", client.ObjectKeyFromObject(virtualIP), err)
			}
		}
	}

	// if err := clientutils.PatchRemoveFinalizer(ctx, r.Client, nic, virtualIPFinalizer); err != nil {
	// 	return ctrl.Result{}, client.IgnoreNotFound(err)
	// }

	if err := clientutils.PatchRemoveFinalizer(ctx, r.Client, virtualIP, virtualIPFinalizer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

func (r *VirtualIPReconciler) reconcile(ctx context.Context, log logr.Logger, virtualIP *networkingv1alpha1.VirtualIP) (ctrl.Result, error) {
	log.V(1).Info("Reconciling VirtualIP")

	if _, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, virtualIP, virtualIPFinalizer); err != nil {
		return ctrl.Result{}, err
	}

	if virtualIP.Spec.TargetRef != nil {
		return r.reconcileBound(ctx, log, virtualIP)
	}
	return r.reconcileUnbound(ctx, log, virtualIP)
}

func (r *VirtualIPReconciler) reconcileBound(ctx context.Context, log logr.Logger, virtualIP *networkingv1alpha1.VirtualIP) (ctrl.Result, error) {
	nic := &networkingv1alpha1.NetworkInterface{}
	nicKey := types.NamespacedName{Name: virtualIP.Spec.TargetRef.Name, Namespace: virtualIP.Namespace}
	if err := r.Get(ctx, nicKey, nic); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get NetworkInterface %s: %w", nicKey, err)
	}

	if nic.Spec.NodeName == nil {
		log.V(1).Info("Network interface attached with VirtualIP is not yet assigned to a node.")
		return ctrl.Result{Requeue: true}, nil
	}

	if nic.Spec.NodeName != nil && *nic.Spec.NodeName != r.Hostname {
		// Network interface related to the VIP doesnt belong to this host.
		// TODO: Handle this better with watches.
		return ctrl.Result{}, nil
	}

	switch virtualIP.Spec.Type {
	case networkingv1alpha1.VirtualIPTypePublic:
		log.V(1).Info("Registering public VirtualIP")

		vipIp := &dpdkproto.InterfaceVIPIP{}
		switch virtualIP.Spec.IPFamily {
		case corev1.IPv4Protocol:
			vipIp.IpVersion = dpdkproto.IPVersion_IPv4
		case corev1.IPv6Protocol:
			vipIp.IpVersion = dpdkproto.IPVersion_IPv6
		}
		if virtualIP.Spec.IP != nil {
			vipIp.Address = []byte(virtualIP.Spec.IP.String())
		}

		var interfaceID string
		var underlayIP *v1alpha1.IP
		if nic.Status.State == networkingv1alpha1.NetworkInterfaceStateReady {
			// get interface UID
			interfaceID = string(nic.Status.UID)
			// get underlay IP
			underlayIP = v1alpha1.MustParseNewIP(nic.Status.PCIDpAddr)
		}

		// Register VIP
		resp, err := r.DPDKClient.AddInterfaceVIP(ctx, &dpdkproto.InterfaceVIPMsg{
			InterfaceID:    []byte(interfaceID),
			InterfaceVIPIP: vipIp,
		})

		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add VirtualIP %s to NetworkInterface %s: %w", client.ObjectKeyFromObject(virtualIP), client.ObjectKeyFromObject(nic), err)
		}

		if resp.Status.Error != dpdkExitSuccess && resp.Status.Error != dpdkRouteAlreadyExists {
			if err := r.patchStatus(ctx, virtualIP, networkingv1alpha1.VirtualIPPhasePending, virtualIP.Status.InterfaceID, underlayIP); err != nil {
				return ctrl.Result{}, err
			}
			log.V(1).Info("failed to add InterfaceVIP", "ExtStatus", resp.Status.Error, "ExtMessage", resp.Status.Message)
			return ctrl.Result{Requeue: true}, nil
		}

		if err := r.patchStatus(ctx, virtualIP, networkingv1alpha1.VirtualIPPhaseBound, interfaceID, underlayIP); err != nil {
			return ctrl.Result{}, err
		}

		// Announce MetalBond VIP
		log.V(1).Info("Announcing PublicIP route", "NIC", nic.Name, "PublicIP", nic.Spec.IP)
		if err := r.announceInterfacePublicVIPRoute(ctx, log, virtualIP, r.PublicVNI, ROUTEADD); err != nil {
			if !strings.Contains(fmt.Sprint(err), "Nexthop already exists") {
				log.Error(err, "failed to announce route")
				return ctrl.Result{}, err
			} else {
				log.Info("Tried to announce the same route for the same VM.")
			}
		}

		log.V(1).Info("Successfully added VirtualIP")
	default:
		log.V(1).Info("Not supported VirtualIP type provided", "VirtualIP", client.ObjectKeyFromObject(virtualIP), "VirtualIPType", virtualIP.Spec.Type)
		return ctrl.Result{}, nil
	}

	log.V(1).Info("Applied VirtualIP", "VirtualIP", client.ObjectKeyFromObject(virtualIP))
	return ctrl.Result{}, nil
}

func (r *VirtualIPReconciler) patchStatus(ctx context.Context, vip *networkingv1alpha1.VirtualIP, phase networkingv1alpha1.VirtualIPPhase, interfaceID string, underlayIP *v1alpha1.IP) error {
	base := vip.DeepCopy()
	now := metav1.Now()
	if vip.Status.Phase != phase {
		vip.Status.LastPhaseTransitionTime = &now
	}
	vip.Status.Phase = phase
	vip.Status.InterfaceID = interfaceID
	vip.Status.UnderlayIP = underlayIP
	return r.Status().Patch(ctx, vip, client.MergeFrom(base))
}

// SetupWithManager sets up the controller with the Manager.
func (r *VirtualIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	log := ctrl.Log.WithName("virtualip").WithName("setup")

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkingv1alpha1.VirtualIP{}, virtualIPField, func(rawObj client.Object) []string {
		vip := rawObj.(*networkingv1alpha1.VirtualIP)
		if vip.Spec.TargetRef != nil {
			return []string{vip.Spec.TargetRef.Name}
		}
		return nil
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.VirtualIP{}).
		Watches(
			&source.Kind{Type: &networkingv1alpha1.NetworkInterface{}},
			r.enqueueByTargetNameReferencingNetworkInterface(log, ctx),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}

func (r *VirtualIPReconciler) enqueueByTargetNameReferencingNetworkInterface(log logr.Logger, ctx context.Context) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(obj client.Object) []ctrl.Request {
		networkInterface := obj.(*networkingv1alpha1.NetworkInterface)
		virtualIPList := &networkingv1alpha1.VirtualIPList{}
		// TODO: we need to filter here for the hostname of the current vmlet
		if err := r.List(ctx, virtualIPList, client.InNamespace(networkInterface.Namespace),
			client.MatchingFields{
				virtualIPField: networkInterface.Name,
			}); err != nil {
			log.Error(err, "Error listing virtual ips targeting network interface")
			return []ctrl.Request{}
		}
		requests := make([]reconcile.Request, 0, len(virtualIPList.Items))
		for _, item := range virtualIPList.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      item.GetName(),
					Namespace: item.GetNamespace(),
				},
			})
		}
		return requests
	})
}

func (r *VirtualIPReconciler) reconcileUnbound(ctx context.Context, log logr.Logger, vip *networkingv1alpha1.VirtualIP) (ctrl.Result, error) {
	if vip.Status.InterfaceID == "" {
		if err := r.patchStatus(ctx, vip, networkingv1alpha1.VirtualIPPhaseUnbound, "", nil); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	msg := &dpdkproto.InterfaceIDMsg{InterfaceID: []byte(vip.Status.InterfaceID)}
	status, err := r.DPDKClient.DeleteInterfaceVIP(ctx, msg)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to delete the VIP %s for machine %s : %w", client.ObjectKeyFromObject(vip), vip.Status.InterfaceID, err)
	}

	if err := status.Error; err != dpdkExitSuccess && err != dpdkInterfaceNotFound {
		log.V(1).Info("failed to delete InterfaceVIP", "Status", status.Error, "Message", status.Message)
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.patchStatus(ctx, vip, networkingv1alpha1.VirtualIPPhaseUnbound, "", nil); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *VirtualIPReconciler) announceInterfacePublicVIPRoute(ctx context.Context, log logr.Logger, vip *networkingv1alpha1.VirtualIP, publicVNI int, action int) error {

	if vip.Spec.IP == nil {
		log.V(1).Info("NetworkInterface is not populated, or Public IP is not set in NIC")
		return nil
	}

	ip := vip.Spec.IP.String() + "/32"
	prefix, err := netip.ParsePrefix(ip)
	if err != nil {
		return fmt.Errorf("failed to convert interface ip to prefix version, reson=%v", err)
	}

	var ipversion mb.IPVersion
	if prefix.Addr().Is4() {
		ipversion = mb.IPV4
	} else {
		ipversion = mb.IPV6
	}

	dest := mb.Destination{
		IPVersion: ipversion,
		Prefix:    prefix,
	}

	if vip.Status.UnderlayIP == nil {
		return fmt.Errorf("UnderlayIP is not populated yet")
	}
	hopIP, err := netip.ParseAddr(vip.Status.UnderlayIP.String())
	if err != nil {
		return fmt.Errorf("invalid nexthop address: %s : %w", vip.Status.UnderlayIP, err)
	}

	hop := mb.NextHop{
		TargetAddress: hopIP,
		TargetVNI:     0,
		NAT:           false,
	}

	if action == ROUTEADD {
		if err = r.MbInstance.AnnounceRoute(mb.VNI(publicVNI), dest, hop); err != nil {
			return fmt.Errorf("failed to announce a local route, reason: %v", err)
		}
	} else {
		if err = r.MbInstance.WithdrawRoute(mb.VNI(publicVNI), dest, hop); err != nil {
			return fmt.Errorf("failed to withdraw a local route, reason: %v", err)
		}
	}

	return nil
}
