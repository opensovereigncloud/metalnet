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
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/go-logr/logr"
	mb "github.com/onmetal/metalbond"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/onmetal/metalnet/api/v1alpha1"
	networkingv1alpha1 "github.com/onmetal/metalnet/api/v1alpha1"
)

const (
	NetworkInterfaceFinalizerName = "networking.metalnet.onmetal.de/networkInterface"
	UnderlayRoute                 = "networking.metalnet.onmetal.de/underlayRoute"
	DpPciAddr                     = "networking.metalnet.onmetal.de/dpPciAddr"
	PciDomain                     = "networking.metalnet.onmetal.de/domain"
	PciSlot                       = "networking.metalnet.onmetal.de/slot"
	PciBus                        = "networking.metalnet.onmetal.de/bus"
	PciFunction                   = "networking.metalnet.onmetal.de/function"
	DpRouteAlreadyAddedError      = 251
	dpdkExitSuccess               = 0
	dpdkInterfaceNotFound         = 450
	dpdkRouteAlreadyExists        = 351
	dpdkPrefixInterfaceNotFound   = 701
)

type NodeDevPCIInfo func(string, int) (map[string]string, error)

// NetworkInterfaceReconciler reconciles a NetworkInterface object
type NetworkInterfaceReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	DPDKClient      dpdkproto.DPDKonmetalClient
	HostName        string
	RouterAddress   string
	PublicVNI       int
	MbInstance      *mb.MetalBond
	DeviceAllocator DeviceAllocator
}

//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkinterfaces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkinterfaces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.metalnet.onmetal.de,resources=networkinterfaces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NetworkInterfaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	ni := &networkingv1alpha1.NetworkInterface{}

	if err := r.Get(ctx, req.NamespacedName, ni); err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Info("unable to fetch NetworkInterface", "NetworkInterface", req, "Error", err)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if *ni.Spec.NodeName != r.HostName {
		return ctrl.Result{}, nil
	}

	network := &networkingv1alpha1.Network{}
	networkKey := client.ObjectKey{
		Namespace: req.NamespacedName.Namespace,
		Name:      ni.Spec.NetworkRef.Name,
	}
	if err := r.Get(ctx, networkKey, network); err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Info("unable to fetch Network", "Network", req, "Error", err)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// delete flow
	if !ni.DeletionTimestamp.IsZero() {
		if ni.Spec.NodeName != nil && *ni.Spec.NodeName != r.HostName {
			return ctrl.Result{}, nil
		}

		log.Info("Delete flow")
		clone := ni.DeepCopy()

		if ni.Status.State == networkingv1alpha1.NetworkInterfaceStateReady {
			interfaceID := string(ni.UID)
			if err := r.deleteInterfaceDPSKServerCall(ctx, interfaceID); err != nil {
				ni.Status.State = networkingv1alpha1.NetworkInterfaceStateError
				if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			pciAddrDetails := &DetailPCIAddr{
				pciDomain: ni.Status.PCIDevice.Domain,
				pciSlot:   ni.Status.PCIDevice.Slot,
				pciBus:    ni.Status.PCIDevice.Bus,
				pciFunc:   ni.Status.PCIDevice.Function,
			}
			dpStr := r.DeviceAllocator.GetNameWithDetails(pciAddrDetails)
			r.DeviceAllocator.FreeDevice(dpStr)
			ni.Status.PCIDevice = nil
		}

		log.V(1).Info("VirtualIP will be deleted as well")
		if ni.Status.VirtualIP != nil && ni.UID != "" {
			msg := &dpdkproto.InterfaceIDMsg{InterfaceID: []byte(ni.UID)}
			status, err := r.DPDKClient.DeleteInterfaceVIP(ctx, msg)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete the VIP %s : %w", ni.Status.VirtualIP, err)
			}

			if err := status.Error; err != dpdkExitSuccess && err != dpdkInterfaceNotFound {
				log.V(1).Info("failed to add InterfaceVIP", "Status", status.Error, "Message", status.Message)
				return ctrl.Result{Requeue: true}, nil
			}

			// Withdraw VIP from MetalBond
			log.V(1).Info("Withdrawing PublicIP route", "PublicIP", ni.Status.VirtualIP)
			if err := r.announceInterfacePublicVIPRoute(ctx, log, ni, r.PublicVNI, ROUTEREMOVE); err != nil {
				if !strings.Contains(fmt.Sprint(err), "Nexthop does not exist") {
					log.Error(err, "failed to remove route")
					return ctrl.Result{}, err
				} else {
					log.Info("Tried to remove the same route for the same VM.")
				}
			}
		}

		log.V(1).Info("Withdrawing Private route", "NIC", ni.Name, "PublicIP", ni.Spec.IPs[0], "VNI", network.Spec.ID)
		if err := r.announceInterfaceLocalRoute(ctx, ni, network.Spec, ROUTEREMOVE); err != nil {
			if !strings.Contains(fmt.Sprint(err), "Nexthop does not exist") {
				return ctrl.Result{}, fmt.Errorf("failed to withdraw a route. %v", err)
			} else {
				log.Info("Tried to remove the same route for the same VM.")
			}
		}

		if len(ni.Status.Prefixes) > 0 {
			deletionList := ni.Status.Prefixes
			for _, prfx := range deletionList {
				prefix := &dpdkproto.Prefix{}
				if prfx.IP().Is4() {
					prefix.IpVersion = dpdkproto.IPVersion_IPv4
				} else {
					prefix.IpVersion = dpdkproto.IPVersion_IPv6
				}
				prefix.Address = []byte(prfx.IP().String())
				prefix.PrefixLength = uint32(prfx.Bits())

				reg := &dpdkproto.InterfacePrefixMsg{
					InterfaceID: &dpdkproto.InterfaceIDMsg{
						InterfaceID: []byte(ni.UID),
					},
					Prefix: prefix,
				}

				log.V(1).Info("DELETE", "reg", reg)
				if err := r.announcePrefix(ctx, log, &prfx, ni.Status.UnderlayIP.String(), network.Spec.ID, ROUTEREMOVE); err != nil {
					return ctrl.Result{}, err
				}
				status, err := r.DPDKClient.DeleteInterfacePrefix(ctx, reg)
				if err != nil {
					return ctrl.Result{}, err
				}
				if status.Error != dpdkExitSuccess && status.Error != dpdkPrefixInterfaceNotFound {
					return ctrl.Result{}, err
				}
			}
		}

		controllerutil.RemoveFinalizer(clone, NetworkInterfaceFinalizerName)
		if err := r.Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Are we still synchron with dp-service and metalbond internal states ?
	if ni.Status.State == networkingv1alpha1.NetworkInterfaceStateReady {
		interfaceID := string(ni.UID)
		_, err := r.getInterfaceDPSKServerCall(ctx, interfaceID)
		if err != nil {
			clone := ni.DeepCopy()
			clone.Status.State = networkingv1alpha1.NetworkInterfaceStateError
			if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		n := &networkingv1alpha1.Network{}
		key := types.NamespacedName{
			Namespace: req.NamespacedName.Namespace,
			Name:      ni.Spec.NetworkRef.Name,
		}
		if err := r.Get(ctx, key, n); err != nil {
			log.Info("unable to fetch Network", "Error", err)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, client.IgnoreNotFound(err)
		}
		if !r.MbInstance.IsSubscribed(mb.VNI(n.Spec.ID)) {
			if err := r.MbInstance.Subscribe(mb.VNI(n.Spec.ID)); err != nil {
				log.Info("duplicate subscription, IGNORED for now due to boostrap of virt networks")
			}
		}
		isAnnounced, err := r.isInterfaceLocalRouteAnnounced(ctx, ni, n.Spec)
		if err == nil && !isAnnounced {
			if err := r.announceInterfaceLocalRoute(ctx, ni, n.Spec, ROUTEADD); err != nil {
				if !strings.Contains(fmt.Sprint(err), "Nexthop already exists") {
					log.Error(err, "failed to announce route")
					return ctrl.Result{}, err
				} else {
					log.Info("Tried to announce the same route for the same VM.")
				}
			}
		}
		if ni.Spec.VirtualIP == nil && ni.Status.VirtualIP != nil {
			log.V(1).Info("VirtualIP deleted")
			if ni.UID != "" {
				msg := &dpdkproto.InterfaceIDMsg{InterfaceID: []byte(ni.UID)}
				status, err := r.DPDKClient.DeleteInterfaceVIP(ctx, msg)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to delete the VIP %s : %w", ni.Status.VirtualIP, err)
				}

				if err := status.Error; err != dpdkExitSuccess && err != dpdkInterfaceNotFound {
					log.V(1).Info("failed to add InterfaceVIP", "Status", status.Error, "Message", status.Message)
					return ctrl.Result{Requeue: true}, nil
				}

				// Withdraw VIP from MetalBond
				log.V(1).Info("Withdrawing PublicIP route", "PublicIP", ni.Status.VirtualIP)
				if err := r.announceInterfacePublicVIPRoute(ctx, log, ni, r.PublicVNI, ROUTEREMOVE); err != nil {
					if !strings.Contains(fmt.Sprint(err), "Nexthop does not exist") {
						log.Error(err, "failed to remove route")
						return ctrl.Result{}, err
					} else {
						log.Info("Tried to remove the same route for the same VM.")
					}
				}
			}
			clone := ni.DeepCopy()
			clone.Status.VirtualIP = nil
			if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		if ni.Spec.VirtualIP != nil {
			log.V(1).Info("Registering public VirtualIP")

			vipIp := &dpdkproto.InterfaceVIPIP{}
			vipIp.IpVersion = dpdkproto.IPVersion_IPv4
			vipIp.Address = []byte(ni.Spec.VirtualIP.String())

			// get interface UID
			interfaceID := string(ni.UID)

			// Register VIP
			resp, err := r.DPDKClient.AddInterfaceVIP(ctx, &dpdkproto.InterfaceVIPMsg{
				InterfaceID:    []byte(interfaceID),
				InterfaceVIPIP: vipIp,
			})

			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to add VirtualIP %s err: %w", ni.Spec.VirtualIP.String(), err)
			}

			if resp.Status.Error != dpdkExitSuccess && resp.Status.Error != dpdkRouteAlreadyExists {
				log.V(1).Info("failed to add InterfaceVIP", "ExtStatus", resp.Status.Error, "ExtMessage", resp.Status.Message)
				return ctrl.Result{Requeue: true}, nil
			}

			clone := ni.DeepCopy()
			clone.Status.VirtualIP = ni.Spec.VirtualIP
			if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
				return ctrl.Result{}, err
			}
			ni = clone

			// Announce MetalBond VIP
			log.V(1).Info("Announcing PublicIP route", "NIC", ni.Name, "PublicIP", ni.Spec.VirtualIP)
			if err := r.announceInterfacePublicVIPRoute(ctx, log, ni, r.PublicVNI, ROUTEADD); err != nil {
				if !strings.Contains(fmt.Sprint(err), "Nexthop already exists") {
					log.Error(err, "failed to announce route")
					return ctrl.Result{}, err
				} else {
					log.Info("Tried to announce the same route for the same VM.")
				}
			}

			log.V(1).Info("Successfully added VirtualIP")
			return ctrl.Result{}, nil
		}

		if r.prefixDeletionNeeded(ctx, log, ni) {
			log.V(1).Info("AliasPrefix delete path")
			finalStatusList := ni.Status.Prefixes
			deletionList := r.prefixCompare(ni.Status.Prefixes, ni.Spec.Prefixes)

			for _, prfx := range deletionList {
				prefix := &dpdkproto.Prefix{}
				if prfx.IP().Is4() {
					prefix.IpVersion = dpdkproto.IPVersion_IPv4
				} else {
					prefix.IpVersion = dpdkproto.IPVersion_IPv6
				}
				prefix.Address = []byte(prfx.IP().String())
				prefix.PrefixLength = uint32(prfx.Bits())

				reg := &dpdkproto.InterfacePrefixMsg{
					InterfaceID: &dpdkproto.InterfaceIDMsg{
						InterfaceID: []byte(ni.UID),
					},
					Prefix: prefix,
				}

				log.V(1).Info("DELETE", "reg", reg)
				if err := r.announcePrefix(ctx, log, &prfx, ni.Status.UnderlayIP.String(), n.Spec.ID, ROUTEREMOVE); err != nil {
					return ctrl.Result{}, err
				}
				status, err := r.DPDKClient.DeleteInterfacePrefix(ctx, reg)
				if err != nil {
					continue
				}
				if status.Error != dpdkExitSuccess && status.Error != dpdkPrefixInterfaceNotFound {
					continue
				}
				finalStatusList = r.prefixRemoveFromList(finalStatusList, &prfx)
			}
			clone := ni.DeepCopy()
			clone.Status.Prefixes = finalStatusList

			if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
				log.Info("unable to update NetworkInterface", "Error", err)
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}
			return ctrl.Result{}, nil
		}

		if ni.Spec.Prefixes != nil && len(ni.Spec.Prefixes) > 0 {
			var specDiffToStatus, resStatus []networkingv1alpha1.IPPrefix

			log.V(1).Info("Registering AliasPrefix(es)")
			if ni.Status.Prefixes != nil {
				specDiffToStatus = r.prefixCompare(ni.Spec.Prefixes, ni.Status.Prefixes)
				if len(specDiffToStatus) == 0 {
					dpPrefixList, err := r.getDPDKPrefixList(ctx, log, ni)
					if err != nil {
						return ctrl.Result{}, err
					}
					for _, pfx := range ni.Status.Prefixes {
						if r.prefixExists(ctx, log, &pfx, dpPrefixList) {
							isAnnounced, err := r.isPrefixAnnounced(ctx, log, &pfx, ni, n.Spec.ID)
							if err == nil && !isAnnounced {
								if err := r.announcePrefix(ctx, log, &pfx, ni.Status.UnderlayIP.String(), n.Spec.ID, ROUTEADD); err != nil {
									return ctrl.Result{}, err
								}
							}
						}
					}
					return ctrl.Result{}, nil
				}
				if len(specDiffToStatus) > 0 {
					resStatus = ni.Status.Prefixes
				}
			} else {
				specDiffToStatus = ni.Spec.Prefixes
			}

			machineID := &dpdkproto.InterfaceIDMsg{
				InterfaceID: []byte(ni.UID),
			}

			for i := 0; i < len(specDiffToStatus); i++ {
				prefix := &dpdkproto.Prefix{}
				if specDiffToStatus[i].IP().Is4() {
					prefix.IpVersion = dpdkproto.IPVersion_IPv4
				} else {
					prefix.IpVersion = dpdkproto.IPVersion_IPv6
				}
				prefix.Address = []byte(specDiffToStatus[i].IP().String())
				prefix.PrefixLength = uint32(specDiffToStatus[i].Bits())

				reg := &dpdkproto.InterfacePrefixMsg{
					InterfaceID: machineID,
					Prefix:      prefix,
				}
				status, err := r.DPDKClient.AddInterfacePrefix(ctx, reg)
				if err != nil {
					continue
				}
				if status.Status.Error != dpdkExitSuccess {
					continue
				}
				resStatus = append(resStatus, specDiffToStatus[i])
				if err := r.announcePrefix(ctx, log, &specDiffToStatus[i], string(status.UnderlayRoute), n.Spec.ID, ROUTEADD); err != nil {
					continue
				}
			}

			if len(resStatus) > 0 {
				clone := ni.DeepCopy()
				clone.Status.Prefixes = resStatus

				if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
					log.Info("unable to update NetworkInterface", "Error", err)
					return ctrl.Result{}, client.IgnoreNotFound(err)
				}
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, nil
	}

	if ni.Status.State == networkingv1alpha1.NetworkInterfaceStatePending {
		return ctrl.Result{}, nil
	}

	n := &networkingv1alpha1.Network{}
	key := types.NamespacedName{
		Namespace: req.NamespacedName.Namespace,
		Name:      ni.Spec.NetworkRef.Name,
	}
	if err := r.Get(ctx, key, n); err != nil {
		log.Info("unable to fetch Network", "Error", err)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, client.IgnoreNotFound(err)
	}

	dpPci := ""
	if ni.Status.PCIDevice != nil {
		pciAddrDetails := &DetailPCIAddr{
			pciDomain: ni.Status.PCIDevice.Domain,
			pciSlot:   ni.Status.PCIDevice.Slot,
			pciBus:    ni.Status.PCIDevice.Bus,
			pciFunc:   ni.Status.PCIDevice.Function,
		}
		dpPci = r.DeviceAllocator.GetNameWithDetails(pciAddrDetails)
	}

	if dpPci == "" {
		newDevice, err := r.DeviceAllocator.ReserveDevice()
		if err != nil {
			log.V(1).Error(err, "PCI device reservation error")
			return ctrl.Result{}, err
		}
		dpPci = newDevice
		log.V(1).Info("Assigning new Network PCI Device", "PCI:", newDevice)
	} else {
		log.V(1).Info("Using assigned Network PCI Device", "PCI:", dpPci)
		r.DeviceAllocator.ReserveDeviceWithName(dpPci)
	}

	_, resp, err := r.addInterfaceDPSKServerCall(ctx, ni, n.Spec, dpPci)
	if err != nil {
		r.DeviceAllocator.FreeDevice(dpPci)
		return ctrl.Result{}, err
	}
	log.Info("AddInterface GRPC call", "resp", resp)

	clone := ni.DeepCopy()

	clone.Status.State = networkingv1alpha1.NetworkInterfaceStatePending
	clone.Status.UnderlayIP = networkingv1alpha1.MustParseNewIP(string(resp.Response.UnderlayRoute))
	detailPci, _ := r.DeviceAllocator.GetDeviceWithName(dpPci)
	PCIDeviceDetails := &networkingv1alpha1.PCIDevice{
		Bus:      detailPci.pciBus,
		Domain:   detailPci.pciDomain,
		Slot:     detailPci.pciSlot,
		Function: detailPci.pciFunc,
	}
	clone.Status.PCIDevice = PCIDeviceDetails
	if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ni = clone
	if err := r.MbInstance.Subscribe(mb.VNI(n.Spec.ID)); err != nil {
		log.Info("duplicate subscription, IGNORED for now due to boostrap of virt networks")
	}

	if err := r.announceInterfaceLocalRoute(ctx, ni, n.Spec, ROUTEADD); err != nil {
		if !strings.Contains(fmt.Sprint(err), "Nexthop already exists") {
			log.Error(err, "failed to announce route")
			return ctrl.Result{}, err
		} else {
			log.Info("Tried to announce the same route for the same VM.")
		}
	}

	if err := r.insertDefaultVNIPublicRoute(ctx, n.Spec.ID); err != nil {
		log.Error(err, "failed to add default route to vni %d", n.Spec.ID)
		return ctrl.Result{}, err
	}

	clone = ni.DeepCopy()

	if clone.DeletionTimestamp.IsZero() && !controllerutil.ContainsFinalizer(clone, NetworkInterfaceFinalizerName) {
		controllerutil.AddFinalizer(clone, NetworkInterfaceFinalizerName)
	}
	clone.Spec.NodeName = &r.HostName

	if err := r.Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
		log.Info("unable to update NetworkInterface", "NetworkInterface", req, "Error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ni = clone

	clone = ni.DeepCopy()
	clone.Status.State = networkingv1alpha1.NetworkInterfaceStateReady

	if err := r.Status().Patch(ctx, clone, client.MergeFrom(ni)); err != nil {
		log.Info("unable to update NetworkInterface", "NetworkInterface", req, "Error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

func (r *NetworkInterfaceReconciler) announceInterfacePublicVIPRoute(ctx context.Context, log logr.Logger, ni *networkingv1alpha1.NetworkInterface, publicVNI int, action int) error {
	niVIP := ni.Spec.VirtualIP
	if action == ROUTEREMOVE {
		niVIP = ni.Status.VirtualIP
	}
	if niVIP == nil {
		log.V(1).Info("Virtual IP is not set in NIC")
		return nil
	}

	ip := niVIP.String() + "/32"
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

	if ni.Status.UnderlayIP == nil {
		return fmt.Errorf("UnderlayIP is not populated yet")
	}
	hopIP, err := netip.ParseAddr(ni.Status.UnderlayIP.String())
	if err != nil {
		return fmt.Errorf("invalid nexthop address: %s : %w", ni.Status.UnderlayIP, err)
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

func (r *NetworkInterfaceReconciler) deleteInterfaceDPSKServerCall(ctx context.Context, interfaceID string) error {
	delInterfaceReq := &dpdkproto.InterfaceIDMsg{
		InterfaceID: []byte(interfaceID),
	}
	status, err := r.DPDKClient.DeleteInterface(ctx, delInterfaceReq)
	if err != nil {
		return err
	}
	if status.Error != 0 && status.Error != 151 { // 151 - interface not found
		return fmt.Errorf("eror during Grpc call, DeleteInterface, code=%v", status.Error)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) getInterfaceDPSKServerCall(ctx context.Context, interfaceID string) (*dpdkproto.GetInterfaceResponse, error) {
	getInterfaceReq := &dpdkproto.InterfaceIDMsg{
		InterfaceID: []byte(interfaceID),
	}
	resp, err := r.DPDKClient.GetInterface(ctx, getInterfaceReq)
	if err != nil {
		return nil, err
	}
	if resp.Status.Error != 0 {
		return nil, fmt.Errorf("eror during Grpc call, GetInterface, code=%v", resp.Status.Error)
	}
	return resp, nil
}

func (r *NetworkInterfaceReconciler) addInterfaceDPSKServerCall(ctx context.Context, ni *networkingv1alpha1.NetworkInterface, nSpec networkingv1alpha1.NetworkSpec, pciAddr string) (string, *dpdkproto.CreateInterfaceResponse, error) {
	interfaceID := string(ni.UID)
	ip := ni.Spec.IPs[0].String()
	createInterfaceReq := &dpdkproto.CreateInterfaceRequest{
		InterfaceType: dpdkproto.InterfaceType_VirtualInterface,
		InterfaceID:   []byte(interfaceID),
		Vni:           uint32(nSpec.ID),
		DeviceName:    pciAddr,
		Ipv4Config: &dpdkproto.IPConfig{
			IpVersion:      dpdkproto.IPVersion_IPv4,
			PrimaryAddress: []byte(ip),
		},
		Ipv6Config: &dpdkproto.IPConfig{
			IpVersion:      dpdkproto.IPVersion_IPv6,
			PrimaryAddress: []byte(RandomIpV6Address()),
		},
	}
	resp, err := r.DPDKClient.CreateInterface(ctx, createInterfaceReq)

	if err != nil {
		return "", nil, err
	}
	if resp.Response.Status.Error != 0 && resp.Response.Status.Error != 109 {
		return "", nil, fmt.Errorf("eror during Grpc call, CreateInterface, code=%v", resp.Response.Status.Error)
	}

	return interfaceID, resp, nil
}

func (r *NetworkInterfaceReconciler) isInterfaceLocalRouteAnnounced(ctx context.Context, ni *networkingv1alpha1.NetworkInterface, nSpec networkingv1alpha1.NetworkSpec) (bool, error) {
	niSpec := ni.Spec
	if niSpec.IPs == nil || ni.Status.State != networkingv1alpha1.NetworkInterfaceStateReady {
		return false, errors.New("parameter nil")
	}
	ip := niSpec.IPs[0].String() + "/32"
	hop, dest, err := prepareMbParameters(ctx, ip, ni.Status.UnderlayIP.String())

	if err != nil {
		return false, err
	}

	if r.MbInstance.IsRouteAnnounced(mb.VNI(nSpec.ID), *dest, *hop) {
		return true, nil
	}
	return false, nil
}

func (r *NetworkInterfaceReconciler) announceInterfaceLocalRoute(ctx context.Context, ni *networkingv1alpha1.NetworkInterface, nSpec networkingv1alpha1.NetworkSpec, action int) error {
	niSpec := ni.Spec
	if niSpec.IPs == nil || ni.Status.State != networkingv1alpha1.NetworkInterfaceStateReady {
		return nil
	}

	ip := niSpec.IPs[0].String() + "/32"
	hop, dest, err := prepareMbParameters(ctx, ip, ni.Status.UnderlayIP.String())

	if err != nil {
		return err
	}

	if action == ROUTEADD {
		if err = r.MbInstance.AnnounceRoute(mb.VNI(nSpec.ID), *dest, *hop); err != nil {
			return fmt.Errorf("failed to announce a local route, reason: %v", err)
		}
	} else {
		if err = r.MbInstance.WithdrawRoute(mb.VNI(nSpec.ID), *dest, *hop); err != nil {
			return fmt.Errorf("failed to withdraw a local route, reason: %v", err)
		}
	}

	return nil
}

func (r *NetworkInterfaceReconciler) announcePrefix(ctx context.Context, log logr.Logger, pfx *networkingv1alpha1.IPPrefix, ulRoute string, nID int32, action int) error {
	ip := pfx.String()
	hop, dest, err := prepareMbParameters(ctx, ip, ulRoute)
	if err != nil {
		return err
	}

	if action == ROUTEADD {
		if err = r.MbInstance.AnnounceRoute(mb.VNI(nID), *dest, *hop); err != nil {
			return fmt.Errorf("failed to announce a local route, reason: %v", err)
		}
	} else {
		if err = r.MbInstance.WithdrawRoute(mb.VNI(nID), *dest, *hop); err != nil {
			if !strings.Contains(fmt.Sprint(err), "Nexthop does not exist") {
				return fmt.Errorf("failed to withdraw a local route, reason: %v", err)
			}
		}
	}

	return nil
}

func (r *NetworkInterfaceReconciler) insertDefaultVNIPublicRoute(ctx context.Context, vni int32) error {

	prefix := &dpdkproto.Prefix{
		PrefixLength: uint32(0),
	}

	prefix.IpVersion = dpdkproto.IPVersion_IPv4 //only ipv4 in overlay is supported so far
	prefix.Address = []byte("0.0.0.0")

	req := &dpdkproto.VNIRouteMsg{
		Vni: &dpdkproto.VNIMsg{Vni: uint32(vni)},
		Route: &dpdkproto.Route{
			IpVersion:      dpdkproto.IPVersion_IPv6, //only ipv4 in overlay is supported so far
			Weight:         100,                      // this field is ignored in dp-service
			Prefix:         prefix,
			NexthopVNI:     uint32(vni),
			NexthopAddress: []byte(r.RouterAddress),
		},
	}

	status, err := r.DPDKClient.AddRoute(ctx, req)
	if err != nil || (status.Error != 0 && status.Error != DpRouteAlreadyAddedError) {
		return fmt.Errorf("cannot add route to dpdk service: %v Status from DPDKClient: %d", err, status.Error)
	}

	return nil
}

func (r *NetworkInterfaceReconciler) prefixCompare(first, second []networkingv1alpha1.IPPrefix) []networkingv1alpha1.IPPrefix {
	var ret []networkingv1alpha1.IPPrefix
	exists := false

	for _, x := range first {
		for _, y := range second {
			if v1alpha1.EqualIPPrefixes(x, y) {
				exists = true
			}
		}
		if !exists {
			ret = append(ret, x)
		} else {
			exists = false
		}
	}

	return ret
}

func (r *NetworkInterfaceReconciler) prefixRemoveFromList(source []networkingv1alpha1.IPPrefix, pfx *networkingv1alpha1.IPPrefix) []networkingv1alpha1.IPPrefix {
	for idx, x := range source {
		if v1alpha1.EqualIPPrefixes(x, *pfx) {
			source[idx] = source[len(source)-1]
			return source[:len(source)-1]
		}
	}
	return nil
}

func (r *NetworkInterfaceReconciler) prefixDeletionNeeded(ctx context.Context, log logr.Logger, ni *networkingv1alpha1.NetworkInterface) bool {
	specPrefixes := ni.Spec.Prefixes
	statusPrefixes := ni.Status.Prefixes

	if statusPrefixes == nil {
		return false
	}

	if specPrefixes == nil && statusPrefixes != nil {
		return true
	}

	resPrefixes := r.prefixCompare(statusPrefixes, specPrefixes)

	return (len(resPrefixes) > 0)
}

func (r *NetworkInterfaceReconciler) getDPDKPrefixList(ctx context.Context, log logr.Logger, ni *networkingv1alpha1.NetworkInterface) (*dpdkproto.PrefixesMsg, error) {
	machineID := &dpdkproto.InterfaceIDMsg{
		InterfaceID: []byte(ni.UID),
	}

	prefixMsg, err := r.DPDKClient.ListInterfacePrefixes(ctx, machineID)
	if err != nil {
		return nil, errors.New("error getting prefix list")
	}
	return prefixMsg, nil
}

func (r *NetworkInterfaceReconciler) prefixExists(ctx context.Context, log logr.Logger, niSpecPrefix *networkingv1alpha1.IPPrefix, prefixMsg *dpdkproto.PrefixesMsg) bool {

	if len(prefixMsg.Prefixes) == 0 {
		return false
	}
	prefix := &dpdkproto.Prefix{}
	if niSpecPrefix.IP().Is4() {
		prefix.IpVersion = dpdkproto.IPVersion_IPv4
	} else {
		prefix.IpVersion = dpdkproto.IPVersion_IPv6
	}
	prefix.Address = []byte(niSpecPrefix.IP().String())
	prefix.PrefixLength = uint32(niSpecPrefix.Bits())

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

func (r *NetworkInterfaceReconciler) isPrefixAnnounced(ctx context.Context, log logr.Logger, pfx *networkingv1alpha1.IPPrefix, ni *networkingv1alpha1.NetworkInterface, nID int32) (bool, error) {
	ip := pfx.String()
	hop, dest, err := prepareMbParameters(ctx, ip, ni.Status.UnderlayIP.String())
	if err != nil {
		return false, err
	}

	if r.MbInstance.IsRouteAnnounced(mb.VNI(nID), *dest, *hop) {
		return true, nil
	}
	return false, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkInterfaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.NetworkInterface{}).
		Complete(r)
}

func RandomIpV6Address() string {
	// TODO: delete after close https://github.com/onmetal/net-dpservice/issues/71
	var ip net.IP
	for i := 0; i < net.IPv6len; i++ {
		number := uint8(rand.Intn(255))
		ip = append(ip, number)
	}
	return ip.String()
}
