// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/jaypipes/ghw"

	"github.com/ironcore-dev/controller-utils/clientutils"
	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkclient "github.com/ironcore-dev/dpservice/go/dpservice-go/client"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	dpdkproto "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"
	"github.com/ironcore-dev/metalbond/pb"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	metalnetclient "github.com/ironcore-dev/metalnet/client"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/ipv6manager"
	"github.com/ironcore-dev/metalnet/metalbond"
	"github.com/ironcore-dev/metalnet/netfns"
	"github.com/ironcore-dev/metalnet/sysfs"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

const (
	networkInterfaceFinalizer = "networking.metalnet.ironcore.dev/networkInterface"
	defaultFirewallRulePrio   = 100
	defaultFirewallRulePrefix = "0.0.0.0/0"

	libvirtMachineUIDAnnotation = "libvirt-provider.ironcore.dev/machine-uid"

	metalnetDeletionMarkAnnotation        = "metalnet.ironcore.dev/ok-to-delete"
	metalnetDeletionGracePeriodAnnotation = "metalnet.ironcore.dev/deletion-grace-period-timestamp"
)

func getIP(ipFamily corev1.IPFamily, ipFamilies []corev1.IPFamily, ips []metalnetv1alpha1.IP) netip.Addr {
	for i, family := range ipFamilies {
		if ipFamily == family {
			return ips[i].Addr
		}
	}
	// If an IP is not specified, then sepcify it as "::" or "0.0.0.0" to disable that ip family on dp-service side
	if ipFamily == corev1.IPv6Protocol {
		return netip.MustParseAddr("::")
	}
	if ipFamily == corev1.IPv4Protocol {
		return netip.MustParseAddr("0.0.0.0")
	}
	return netip.Addr{}
}

func getNetworkInterfaceIP(ipFamily corev1.IPFamily, nic *metalnetv1alpha1.NetworkInterface) netip.Addr {
	return getIP(ipFamily, nic.Spec.IPFamilies, nic.Spec.IPs)
}

func getNetworkInterfaceIPs(nic *metalnetv1alpha1.NetworkInterface) []netip.Addr {
	res := make([]netip.Addr, len(nic.Spec.IPs))
	for i, ip := range nic.Spec.IPs {
		res[i] = ip.Addr
	}
	return res
}

// NetworkInterfaceReconciler reconciles a NetworkInterface object
type NetworkInterfaceReconciler struct {
	client.Client
	record.EventRecorder

	Scheme *runtime.Scheme

	DPDK      dpdkclient.Client
	RouteUtil metalbond.RouteUtil

	NetFnsManager *netfns.Manager
	SysFS         sysfs.FS

	PfToVfOffset                int
	NodeName                    string
	PublicVNI                   int
	EnableIPv6Support           bool
	BluefieldDetected           bool
	BluefieldHostDefaultBusAddr string
	MultiportEswitchMode        bool
	TapDeviceMode               bool
	Control                     *control.ReconcileControl
	LibvirtMachineUIDPath       string

	// IPv6 CIDR for address reservation generation
	IPv6CIDR       string
	ControllerID   string
	ControllerHash string
	ReadyNeeded    int
}

//+kubebuilder:rbac:groups=networking.metalnet.ironcore.dev,resources=networkinterfaces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.metalnet.ironcore.dev,resources=networkinterfaces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.metalnet.ironcore.dev,resources=networkinterfaces/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.metalnet.ironcore.dev,resources=networks,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.metalnet.ironcore.dev,resources=loadbalancers,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NetworkInterfaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	if r.Control.ShouldSkip() {
		log.V(1).Info("Skipping reconcile")
		return ctrl.Result{}, nil
	} else {
		nic := &metalnetv1alpha1.NetworkInterface{}

		if err := r.Get(ctx, req.NamespacedName, nic); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}

		if !isNetworkInterfaceAssignedToNode(nic, r.NodeName) {
			log.V(1).Info("Network interface is not assigned to this node", "NodeName", nic.Spec.NodeName)
			return ctrl.Result{}, nil
		}

		return r.reconcileExists(ctx, log, nic)
	}
}

func (r *NetworkInterfaceReconciler) reconcileExists(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) (ctrl.Result, error) {
	if !nic.DeletionTimestamp.IsZero() {
		return r.delete(ctx, log, nic)
	}

	// Handle IP reservations first
	if requeue, err := r.reconcileReservations(ctx, log, nic); requeue || err != nil {
		return ctrl.Result{Requeue: requeue}, err
	}

	return r.reconcile(ctx, log, nic)
}

func NetIPAddrPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, addr.BitLen())
}

func (r *NetworkInterfaceReconciler) isValidIPConfiguration(ips []metalnetv1alpha1.IP, ipFamilies []corev1.IPFamily) (bool, error) {
	var ipv4Count, ipv6Count int

	for _, ip := range ips {
		if ip.Is4() {
			ipv4Count++
		} else if ip.Is6() {
			ipv6Count++
		}
	}

	if !r.EnableIPv6Support && ipv6Count >= 1 {
		return false, fmt.Errorf("ipv6 flag not enabled but ipv6 address set on interface")
	}

	if ipv4Count > 1 || ipv6Count > 1 {
		return false, fmt.Errorf("more than one IPv4 or IPv6 address is not allowed ")
	}

	ipFamilySet := make(map[corev1.IPFamily]struct{})
	for _, ipFamily := range ipFamilies {
		if _, exists := ipFamilySet[ipFamily]; exists {
			return false, fmt.Errorf("duplicate IPFamily is not allowed")
		}
		ipFamilySet[ipFamily] = struct{}{}
	}

	return true, nil
}

func (r *NetworkInterfaceReconciler) isValidInterfaceSpec(spec *metalnetv1alpha1.NetworkInterfaceSpec) (bool, error) {
	isValid, err := r.isValidIPConfiguration(spec.IPs, spec.IPFamilies)
	if !isValid {
		return false, err
	}

	isValid, err = r.isValidMeteringParams(spec.MeteringRate)
	if !isValid {
		return false, err
	}

	return true, nil
}

func (r *NetworkInterfaceReconciler) releaseNetFnIfClaimExists(uid types.UID) error {
	if err := r.NetFnsManager.Release(uid); err != nil && !errors.Is(err, netfns.ErrClaimNotFound) {
		return fmt.Errorf("error releasing claim: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteDPDKVirtualIPIfExists(ctx context.Context, nic *metalnetv1alpha1.NetworkInterface) error {
	if _, err := r.DPDK.DeleteVirtualIP(
		ctx,
		string(nic.UID),
		dpdkerrors.Ignore(dpdkerrors.NO_VM),
	); err != nil {
		return fmt.Errorf("error deleting dpdk virtual ip: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) removeVirtualIPRouteIfExists(ctx context.Context, virtualIP, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.WithdrawRoute(ctx, metalbond.VNI(r.PublicVNI), metalbond.Destination{
		Prefix: NetIPAddrPrefix(virtualIP),
	}, metalbond.NextHop{
		TargetAddress: underlayRoute,
		TargetVNI:     0,
		TargetHopType: pb.NextHopType_STANDARD,
	}); metalbond.IgnoreNextHopNotFoundError(err) != nil {
		return fmt.Errorf("error removing metalbond route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) addVirtualIPRouteIfNotExists(ctx context.Context, virtualIP, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.AnnounceRoute(ctx, metalbond.VNI(r.PublicVNI), metalbond.Destination{
		Prefix: NetIPAddrPrefix(virtualIP),
	}, metalbond.NextHop{
		TargetAddress: underlayRoute,
		TargetVNI:     0,
		TargetHopType: pb.NextHopType_STANDARD,
	}); metalbond.IgnoreNextHopAlreadyExistsError(err) != nil {
		return fmt.Errorf("error adding metalbond route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) addInterfaceRouteIfNotExists(ctx context.Context, vni uint32, ip, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.AnnounceRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: NetIPAddrPrefix(ip),
	}, metalbond.NextHop{
		TargetVNI:     0,
		TargetAddress: underlayRoute,
	}); metalbond.IgnoreNextHopAlreadyExistsError(err) != nil {
		return fmt.Errorf("error adding interface route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) addInterfaceRoutesIfNotExist(ctx context.Context, log logr.Logger, vni uint32, ips []netip.Addr, underlayRoute netip.Addr) error {
	for _, localAddr := range ips {
		if err := r.addInterfaceRouteIfNotExists(ctx, vni, localAddr, underlayRoute); err != nil {
			return fmt.Errorf("[local address %s] %w", localAddr, err)
		}
		if localAddr.Is6() {
			log.V(1).Info("Adding routable ipv6 route if not exists")
			if err := r.addVirtualIPRouteIfNotExists(ctx, localAddr, underlayRoute); err != nil {
				return err
			}
			log.V(1).Info("Added routable ipv6 route if not existed")
		}
	}
	return nil
}

func (r *NetworkInterfaceReconciler) removeInterfaceRouteIfExists(ctx context.Context, vni uint32, ip, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.WithdrawRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: NetIPAddrPrefix(ip),
	}, metalbond.NextHop{
		TargetVNI:     0,
		TargetAddress: underlayRoute,
	}); metalbond.IgnoreNextHopNotFoundError(err) != nil {
		return fmt.Errorf("error removing interface route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) removeInterfaceRoutesIfExist(ctx context.Context, log logr.Logger, vni uint32, ips []netip.Addr, underlayRoute netip.Addr) error {
	for _, localAddr := range ips {
		if err := r.removeInterfaceRouteIfExists(ctx, vni, localAddr, underlayRoute); err != nil {
			return fmt.Errorf("[local address %s] %w", localAddr, err)
		}
		if localAddr.Is6() {
			log.V(1).Info("Removing routable ipv6 route if exists")
			if err := r.removeVirtualIPRouteIfExists(ctx, localAddr, underlayRoute); err != nil {
				return err
			}
			log.V(1).Info("Removed routable ipv6 route if existed")
		}
	}
	return nil
}

func (r *NetworkInterfaceReconciler) addPrefixRouteIfNotExists(ctx context.Context, vni uint32, prefix netip.Prefix, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.AnnounceRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: prefix,
	}, metalbond.NextHop{
		TargetVNI:     0,
		TargetAddress: underlayRoute,
		TargetHopType: pb.NextHopType_STANDARD,
	}); metalbond.IgnoreNextHopAlreadyExistsError(err) != nil {
		return fmt.Errorf("error adding prefix route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) removePrefixRouteIfExists(ctx context.Context, vni uint32, prefix netip.Prefix, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.WithdrawRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: prefix,
	}, metalbond.NextHop{
		TargetVNI:     0,
		TargetAddress: underlayRoute,
		TargetHopType: pb.NextHopType_STANDARD,
	}); metalbond.IgnoreNextHopNotFoundError(err) != nil {
		return fmt.Errorf("error removing prefix route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) addLBTargetRouteIfNotExists(ctx context.Context, vni uint32, prefix netip.Prefix, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.AnnounceRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: prefix,
	}, metalbond.NextHop{
		TargetVNI:     0,
		TargetAddress: underlayRoute,
		TargetHopType: pb.NextHopType_LOADBALANCER_TARGET,
	}); metalbond.IgnoreNextHopAlreadyExistsError(err) != nil {
		return fmt.Errorf("error adding lb target route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) removeLBTargetRouteIfExists(ctx context.Context, vni uint32, prefix netip.Prefix, underlayRoute netip.Addr) error {
	if err := r.RouteUtil.WithdrawRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: prefix,
	}, metalbond.NextHop{
		TargetVNI:     0,
		TargetAddress: underlayRoute,
		TargetHopType: pb.NextHopType_LOADBALANCER_TARGET,
	}); metalbond.IgnoreNextHopNotFoundError(err) != nil {
		return fmt.Errorf("error removing prefix route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) fillTCPUDPFilter(ctx context.Context, specFirewallRule *metalnetv1alpha1.FirewallRule, protocolFilter *dpdkproto.ProtocolFilter) error {
	var SrcPortLower, DstPortLower, SrcPortUpper, DstPortUpper int32
	if specFirewallRule.ProtocolMatch.PortRange != nil {
		if specFirewallRule.ProtocolMatch.PortRange.SrcPort != nil {
			SrcPortLower = *specFirewallRule.ProtocolMatch.PortRange.SrcPort
			SrcPortUpper = specFirewallRule.ProtocolMatch.PortRange.EndSrcPort
		} else {
			SrcPortLower = -1
			SrcPortUpper = -1
		}
		if specFirewallRule.ProtocolMatch.PortRange.DstPort != nil {
			DstPortLower = *specFirewallRule.ProtocolMatch.PortRange.DstPort
			DstPortUpper = specFirewallRule.ProtocolMatch.PortRange.EndDstPort
		} else {
			DstPortLower = -1
			DstPortUpper = -1
		}
	} else {
		SrcPortLower = -1
		SrcPortUpper = -1
		DstPortLower = -1
		DstPortUpper = -1
	}
	switch *specFirewallRule.ProtocolMatch.ProtocolType {
	case metalnetv1alpha1.FirewallRuleProtocolTypeTCP:
		protocolFilter.Filter = &dpdkproto.ProtocolFilter_Tcp{Tcp: &dpdkproto.TcpFilter{
			SrcPortLower: SrcPortLower,
			SrcPortUpper: SrcPortUpper,
			DstPortLower: DstPortLower,
			DstPortUpper: DstPortUpper,
		}}
	case metalnetv1alpha1.FirewallRuleProtocolTypeUDP:
		protocolFilter.Filter = &dpdkproto.ProtocolFilter_Udp{Udp: &dpdkproto.UdpFilter{
			SrcPortLower: SrcPortLower,
			SrcPortUpper: SrcPortUpper,
			DstPortLower: DstPortLower,
			DstPortUpper: DstPortUpper,
		}}
	}
	return nil
}

func (r *NetworkInterfaceReconciler) createDPDKFwRule(ctx context.Context, nic *metalnetv1alpha1.NetworkInterface, specFirewallRule *metalnetv1alpha1.FirewallRule) error {
	var (
		protocolFilter dpdkproto.ProtocolFilter
		priority       uint32 = defaultFirewallRulePrio
		sourcePrefix   metalnetv1alpha1.IPPrefix
		destPrefix     metalnetv1alpha1.IPPrefix
	)

	switch *specFirewallRule.ProtocolMatch.ProtocolType {
	case metalnetv1alpha1.FirewallRuleProtocolTypeICMP:
		var icmpType, icmpCode int32
		if specFirewallRule.ProtocolMatch.ICMP != nil {
			if specFirewallRule.ProtocolMatch.ICMP.IcmpType != nil {
				icmpType = *specFirewallRule.ProtocolMatch.ICMP.IcmpType
			} else {
				icmpType = -1
			}
			if specFirewallRule.ProtocolMatch.ICMP.IcmpCode != nil {
				icmpCode = *specFirewallRule.ProtocolMatch.ICMP.IcmpCode
			} else {
				icmpCode = -1
			}
		} else {
			icmpCode = -1
			icmpType = -1
		}
		protocolFilter.Filter = &dpdkproto.ProtocolFilter_Icmp{Icmp: &dpdkproto.IcmpFilter{
			IcmpType: icmpType,
			IcmpCode: icmpCode,
		}}
	case metalnetv1alpha1.FirewallRuleProtocolTypeUDP, metalnetv1alpha1.FirewallRuleProtocolTypeTCP:
		if err := r.fillTCPUDPFilter(ctx, specFirewallRule, &protocolFilter); err != nil {
			return fmt.Errorf("error filling TCP/UDP filter: %w", err)
		}
	default:
		protocolFilter.Filter = nil
	}

	if specFirewallRule.Priority != nil {
		priority = uint32(*specFirewallRule.Priority)
	}

	if specFirewallRule.SourcePrefix == nil {
		sourcePrefix.Prefix = netip.MustParsePrefix(defaultFirewallRulePrefix)
	} else {
		sourcePrefix.Prefix = specFirewallRule.SourcePrefix.Prefix
	}

	if specFirewallRule.DestinationPrefix == nil {
		destPrefix.Prefix = netip.MustParsePrefix(defaultFirewallRulePrefix)
	} else {
		destPrefix.Prefix = specFirewallRule.DestinationPrefix.Prefix
	}

	fwrule, err := r.DPDK.CreateFirewallRule(ctx, &dpdk.FirewallRule{
		TypeMeta: dpdk.TypeMeta{Kind: dpdk.FirewallRuleKind},
		FirewallRuleMeta: dpdk.FirewallRuleMeta{
			InterfaceID: string(nic.UID),
		},
		Spec: dpdk.FirewallRuleSpec{
			RuleID:            string(specFirewallRule.FirewallRuleID),
			TrafficDirection:  string(specFirewallRule.Direction),
			FirewallAction:    string(specFirewallRule.Action),
			Priority:          priority,
			SourcePrefix:      &sourcePrefix.Prefix,
			DestinationPrefix: &destPrefix.Prefix,
			ProtocolFilter: &dpdkproto.ProtocolFilter{
				Filter: protocolFilter.Filter,
			},
		},
	})
	if err != nil && fwrule.Status.Code == 0 {
		return fmt.Errorf("error adding firewall rule: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteDPDKfwRuleIDIfExists(ctx context.Context, nicUID, ruleUID string) error {
	if _, err := r.DPDK.DeleteFirewallRule(
		ctx,
		nicUID,
		ruleUID,
		dpdkerrors.Ignore(dpdkerrors.NO_VM, dpdkerrors.NOT_FOUND),
	); err != nil {
		return fmt.Errorf("error deleting firewall rule: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteDPDKLBTargetIfExists(ctx context.Context, nicUID types.UID, prefix netip.Prefix) error {
	if _, err := r.DPDK.DeleteLoadBalancerPrefix(
		ctx,
		string(nicUID),
		&prefix,
		dpdkerrors.Ignore(dpdkerrors.NO_VM, dpdkerrors.NOT_FOUND),
	); err != nil {
		return fmt.Errorf("error deleting lb prefix: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteDPDKPrefixIfExists(ctx context.Context, nicUID types.UID, prefix netip.Prefix) error {
	if _, err := r.DPDK.DeletePrefix(
		ctx,
		string(nicUID),
		&prefix,
		dpdkerrors.Ignore(dpdkerrors.NO_VM, dpdkerrors.NOT_FOUND),
	); err != nil {
		return fmt.Errorf("error deleting prefix: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteDPDKInterfaceIfExists(ctx context.Context, uid types.UID) error {
	if _, err := r.DPDK.DeleteInterface(
		ctx,
		string(uid),
		dpdkerrors.Ignore(dpdkerrors.NOT_FOUND),
	); err != nil {
		return fmt.Errorf("error deleting interface: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) reconcileNATIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, vni uint32) error {
	if nic.Spec.NAT != nil && nic.Spec.NAT.IP != nil {
		natIP := nic.Spec.NAT.IP.Addr
		log = log.WithValues("NatIP", natIP)
		log.V(1).Info("Apply nat ip")
		return r.applyNATIP(ctx, log, nic, natIP, vni)
	}

	log.V(1).Info("Delete nat ip")
	return r.deleteNATIP(ctx, log, nic, vni)
}

func (r *NetworkInterfaceReconciler) applyNATIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, natIP netip.Addr, vni uint32) error {
	log.V(1).Info("Getting dpdk nat ip")
	dpdkNAT, err := r.DPDK.GetNat(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM, dpdkerrors.SNAT_NO_DATA) {
			return fmt.Errorf("error getting dpdk nat ip: %w", err)
		}

		log.V(1).Info("DPDK nat ip does not exist, creating it")
		return r.createNATIP(ctx, log, nic, natIP, vni)
	}

	underlayRoute := dpdkNAT.Spec.UnderlayRoute
	existingNATIP := *dpdkNAT.Spec.NatIP
	if existingNATIP == natIP && dpdkNAT.Spec.MinPort == uint32(nic.Spec.NAT.Port) && dpdkNAT.Spec.MaxPort == uint32(nic.Spec.NAT.EndPort) {
		log.V(1).Info("DPDK nat ip is up-to-date, adding metalbond route if not exists")
		if err := r.addNATIPRouteIfNotExists(ctx, dpdkNAT, *underlayRoute, vni); err != nil {
			return err
		}
		log.V(1).Info("Ensured metalbond route exists")
		return nil
	}

	log.V(1).Info("NAT ip and/or NAT ports are not up-to-date", "ExistingNATIP", existingNATIP, "MinPort", dpdkNAT.Spec.MinPort, "MaxPort", dpdkNAT.Spec.MaxPort)

	log.V(1).Info("Delete existing nat ip")
	if err := r.deleteExistingNATIP(ctx, log, nic, dpdkNAT, *underlayRoute, vni); err != nil {
		return err
	}
	log.V(1).Info("Deleted existing nat ip")

	log.V(1).Info("Creating nat ip")
	if err := r.createNATIP(ctx, log, nic, natIP, vni); err != nil {
		return err
	}
	log.V(1).Info("Created nat ip")
	return nil
}

func (r *NetworkInterfaceReconciler) createNATIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, natIP netip.Addr, vni uint32) error {
	underlayRoute := netip.MustParseAddr(nic.Status.Reservation.NatIP.Underlay)
	natLocal, err := r.DPDK.CreateNat(ctx, &dpdk.Nat{
		NatMeta: dpdk.NatMeta{InterfaceID: string(nic.UID)},
		Spec: dpdk.NatSpec{
			NatIP:         &natIP,
			MinPort:       uint32(nic.Spec.NAT.Port),
			MaxPort:       uint32(nic.Spec.NAT.EndPort),
			UnderlayRoute: &underlayRoute,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating dpdk nat ip: %w", err)
	}
	log.V(1).Info("Adding nat ip route if not exists")
	if err := r.addNATIPRouteIfNotExists(ctx, natLocal, *natLocal.Spec.UnderlayRoute, vni); err != nil {
		return err
	}
	log.V(1).Info("Added nat ip route if not existed")
	return nil
}

func (r *NetworkInterfaceReconciler) deleteNATIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, vni uint32) error {
	log.V(1).Info("Getting dpdk nat ip if exists")
	dpdkVIP, err := r.DPDK.GetNat(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM, dpdkerrors.SNAT_NO_DATA) {
			return fmt.Errorf("error getting dpdk nat ip: %w", err)
		}

		log.V(1).Info("DPDK nat ip does not exist")
		return nil
	}

	underlayRoute := dpdkVIP.Spec.UnderlayRoute
	natIP := dpdkVIP.Spec.NatIP
	log.V(1).Info("NAT ip exists", "ExistingNATIP", natIP)
	return r.deleteExistingNATIP(ctx, log, nic, dpdkVIP, *underlayRoute, vni)
}

func (r *NetworkInterfaceReconciler) deleteExistingNATIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, natLocal *dpdk.Nat, underlayRoute netip.Addr, vni uint32) error {
	log.V(1).Info("Removing nat ip route if exists")
	if err := r.removeNATIPRouteIfExists(ctx, natLocal, underlayRoute, vni); err != nil {
		return err
	}
	log.V(1).Info("Removed nat ip route if existed")

	log.V(1).Info("Deleting dpdk nat ip if exists")
	if err := r.deleteDPDKNATIPIfExists(ctx, nic); err != nil {
		return err
	}
	log.V(1).Info("Deleted dpdk nat ip if existed")
	return nil
}

func (r *NetworkInterfaceReconciler) deleteDPDKNATIPIfExists(ctx context.Context, nic *metalnetv1alpha1.NetworkInterface) error {
	if _, err := r.DPDK.DeleteNat(
		ctx,
		string(nic.UID),
		dpdkerrors.Ignore(dpdkerrors.NO_VM),
	); err != nil {
		return fmt.Errorf("error deleting dpdk nat ip: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) removeNATIPRouteIfExists(ctx context.Context, natLocal *dpdk.Nat, underlayRoute netip.Addr, vni uint32) error {
	if err := r.RouteUtil.WithdrawRoute(ctx, metalbond.VNI(r.PublicVNI), metalbond.Destination{
		Prefix: NetIPAddrPrefix(*natLocal.Spec.NatIP),
	}, metalbond.NextHop{
		TargetAddress: underlayRoute,
		TargetVNI:     0,
		TargetHopType: pb.NextHopType_STANDARD,
	}); metalbond.IgnoreNextHopNotFoundError(err) != nil {
		return fmt.Errorf("error removing metalbond route: %w", err)
	}
	if err := r.RouteUtil.WithdrawRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: NetIPAddrPrefix(*natLocal.Spec.NatIP),
	}, metalbond.NextHop{
		TargetAddress:    underlayRoute,
		TargetVNI:        0,
		TargetHopType:    pb.NextHopType_NAT,
		TargetNATMinPort: uint16(natLocal.Spec.MinPort),
		TargetNATMaxPort: uint16(natLocal.Spec.MaxPort),
	}); metalbond.IgnoreNextHopNotFoundError(err) != nil {
		return fmt.Errorf("error removing metalbond route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) addNATIPRouteIfNotExists(ctx context.Context, natLocal *dpdk.Nat, underlayRoute netip.Addr, vni uint32) error {
	if err := r.RouteUtil.AnnounceRoute(ctx, metalbond.VNI(r.PublicVNI), metalbond.Destination{
		Prefix: NetIPAddrPrefix(*natLocal.Spec.NatIP),
	}, metalbond.NextHop{
		TargetAddress: underlayRoute,
		TargetVNI:     0,
		TargetHopType: pb.NextHopType_STANDARD,
	}); metalbond.IgnoreNextHopAlreadyExistsError(err) != nil {
		return fmt.Errorf("error adding metalbond route: %w", err)
	}
	if err := r.RouteUtil.AnnounceRoute(ctx, metalbond.VNI(vni), metalbond.Destination{
		Prefix: NetIPAddrPrefix(*natLocal.Spec.NatIP),
	}, metalbond.NextHop{
		TargetAddress:    underlayRoute,
		TargetVNI:        0,
		TargetHopType:    pb.NextHopType_NAT,
		TargetNATMinPort: uint16(natLocal.Spec.MinPort),
		TargetNATMaxPort: uint16(natLocal.Spec.MaxPort),
	}); metalbond.IgnoreNextHopAlreadyExistsError(err) != nil {
		return fmt.Errorf("error adding metalbond route: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) reconcileVirtualIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) error {
	if nic.Spec.VirtualIP != nil {
		virtualIP := nic.Spec.VirtualIP.Addr
		log = log.WithValues("VirtualIP", virtualIP)
		log.V(1).Info("Apply virtual ip")
		return r.applyVirtualIP(ctx, log, nic, virtualIP)
	}

	log.V(1).Info("Delete virtual ip")
	return r.deleteVirtualIP(ctx, log, nic)
}

func (r *NetworkInterfaceReconciler) applyVirtualIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, virtualIP netip.Addr) error {
	log.V(1).Info("Getting dpdk virtual ip")
	dpdkVIP, err := r.DPDK.GetVirtualIP(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM, dpdkerrors.SNAT_NO_DATA) {
			return fmt.Errorf("error getting dpdk virtual ip: %w", err)
		}

		log.V(1).Info("DPDK virtual ip does not exist, creating it")
		return r.createVirtualIP(ctx, log, nic, virtualIP)
	}
	underlayRoute := dpdkVIP.Spec.UnderlayRoute
	existingVirtualIP := *dpdkVIP.Spec.IP
	if existingVirtualIP == virtualIP {
		log.V(1).Info("DPDK virtual ip is up-to-date, adding metalbond route if not exists")
		if err := r.addVirtualIPRouteIfNotExists(ctx, virtualIP, *underlayRoute); err != nil {
			return err
		}
		log.V(1).Info("Ensured metalbond route exists")
		return nil
	}

	log.V(1).Info("Virtual ip is not up-to-date", "ExistingVirtualIP", existingVirtualIP)

	log.V(1).Info("Delete existing virtual ip")
	if err := r.deleteExistingVirtualIP(ctx, log, nic, existingVirtualIP, *underlayRoute); err != nil {
		return err
	}
	log.V(1).Info("Deleted existing virtual ip")

	log.V(1).Info("Creating virtual ip")
	if err := r.createVirtualIP(ctx, log, nic, virtualIP); err != nil {
		return err
	}
	log.V(1).Info("Created virtual ip")
	return nil
}

func (r *NetworkInterfaceReconciler) createVirtualIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, virtualIP netip.Addr) error {
	underlayRoute := netip.MustParseAddr(nic.Status.Reservation.VirtualIP.Underlay)
	dpdkVIP, err := r.DPDK.CreateVirtualIP(ctx, &dpdk.VirtualIP{
		VirtualIPMeta: dpdk.VirtualIPMeta{InterfaceID: string(nic.UID)},
		Spec:          dpdk.VirtualIPSpec{IP: &virtualIP, UnderlayRoute: &underlayRoute},
	})
	if err != nil {
		if dpdkerrors.IsStatusErrorCode(err, dpdkerrors.DNAT_EXISTS) {
			natIP := virtualIP
			nats, err := r.DPDK.ListNeighborNats(ctx, &natIP)
			if err != nil {
				return fmt.Errorf("error listing neighbor nats for ip %s: %w", natIP.String(), err)
			}

			if len(nats.Items) > 0 {
				log.Info(fmt.Sprintf("Cleanup stale neighbor nats for ip %s", natIP.String()))
				for _, nat := range nats.Items {
					// Delete stale NAT entry
					if _, err := r.DPDK.DeleteNeighborNat(ctx, &dpdk.NeighborNat{
						NeighborNatMeta: dpdk.NeighborNatMeta{
							NatIP: &natIP,
						},
						Spec: dpdk.NeighborNatSpec{
							Vni:           nat.Spec.Vni,
							MinPort:       nat.Spec.MinPort,
							MaxPort:       nat.Spec.MaxPort,
							UnderlayRoute: nat.Spec.UnderlayRoute,
						},
					}, dpdkerrors.Ignore(dpdkerrors.NOT_FOUND),
					); err != nil {
						return fmt.Errorf("error deleting old nat route for ip %s (%d-%d): %w", natIP.String(), nat.Spec.MinPort, nat.Spec.MaxPort, err)
					}
				}
			}
		}
		// force reconcile
		return fmt.Errorf("error creating dpdk virtual ip: %w", err)
	}

	log.V(1).Info("Adding virtual ip route if not exists")
	if err := r.addVirtualIPRouteIfNotExists(ctx, virtualIP, *dpdkVIP.Spec.UnderlayRoute); err != nil {
		return err
	}
	log.V(1).Info("Added virtual ip route if not existed")
	return nil
}

func (r *NetworkInterfaceReconciler) deleteVirtualIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) error {
	log.V(1).Info("Getting dpdk virtual ip if exists")
	dpdkVIP, err := r.DPDK.GetVirtualIP(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM, dpdkerrors.SNAT_NO_DATA) {
			return fmt.Errorf("error getting dpdk virtual ip: %w", err)
		}

		log.V(1).Info("DPDK virtual ip does not exist")
		return nil
	}

	virtualIP := *dpdkVIP.Spec.IP
	underlayRoute := *dpdkVIP.Spec.UnderlayRoute
	log.V(1).Info("Virtual ip exists", "ExistingVirtualIP", virtualIP, "UnderlayRoute", underlayRoute)
	return r.deleteExistingVirtualIP(ctx, log, nic, virtualIP, underlayRoute)
}

func (r *NetworkInterfaceReconciler) deleteExistingVirtualIP(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, virtualIP, underlayRoute netip.Addr) error {
	log.V(1).Info("Removing virtual ip route if exists")
	if err := r.removeVirtualIPRouteIfExists(ctx, virtualIP, underlayRoute); err != nil {
		return err
	}
	log.V(1).Info("Removed virtual ip route if existed")

	log.V(1).Info("Deleting dpdk virtual ip if exists")
	if err := r.deleteDPDKVirtualIPIfExists(ctx, nic); err != nil {
		return err
	}
	log.V(1).Info("Deleted dpdk virtual ip if existed")
	return nil
}

func (r *NetworkInterfaceReconciler) reconcile(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) (ctrl.Result, error) {
	log.V(1).Info("Reconcile")

	// Check if we should proceed with reconciliation based on controller status
	// Only proceed if status differs by observed generation or controller hash and not ready
	for _, cs := range nic.Status.ControllerStatuses {
		if cs.ControllerID == r.ControllerID {
			// Skip reconciliation if this controller has already processed this generation with the same hash
			// and the controller is already reporting ready
			if cs.ObservedGeneration == nic.Generation &&
				cs.ControllerHash == r.ControllerHash &&
				cs.State == string(metalnetv1alpha1.NetworkInterfaceStateReady) {
				log.V(1).Info("Skipping reconciliation - no changes detected for this controller instance",
					"controllerID", r.ControllerID,
					"observedGeneration", cs.ObservedGeneration,
					"currentGeneration", nic.Generation,
					"controllerHash", cs.ControllerHash)
				return ctrl.Result{}, nil
			}
			break
		}
	}

	log.V(1).Info("Ensuring finalizer")
	modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, nic, r.finalizer())
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error ensuring finalizer: %w", err)
	}
	if modified {
		log.V(1).Info("Added finalizer")
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
	}
	log.V(1).Info("Ensured finalizer")

	// TODO(balpert): in current situation this will never be entered due to the changes of ironcore-net.
	// the libvirt-provider now creates the ironcore-net nic and metalnetlet will create the metalnet nic.
	// there is no mechanism to broker the annotations for involved nic objects.
	// get the annotation
	machineUID, hasAnnotation := nic.Annotations[libvirtMachineUIDAnnotation]
	if hasAnnotation {
		log.V(1).Info("Check for existing machine UID", "machineUID", machineUID)
		// iterate through libvirt subdir
		dirInfo, err := os.ReadDir(r.LibvirtMachineUIDPath)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error reading virtlet directory: %w", err)
		}

		// check if there is a match for the uid
		hasUID := false
		for _, d := range dirInfo {
			if !d.IsDir() {
				continue
			}
			if machineUID == d.Name() {
				log.V(1).Info("Machine UID is tracked, continue reconcile", "machineUID", machineUID)
				hasUID = true
				break
			}
		}

		if hasUID {
			baseNIC := nic.DeepCopy()
			if nic.Annotations == nil {
				nic.Annotations = make(map[string]string)
			}

			// remove label "ok-to-delete"
			// remove timestamp "grace-period"
			requiresPatch := false
			if _, hasDeletionMarkAnnotation := nic.Annotations[metalnetDeletionMarkAnnotation]; hasDeletionMarkAnnotation {
				requiresPatch = true
				delete(nic.Annotations, metalnetDeletionMarkAnnotation)
			}
			if _, hasDeletionGracePeriodTimestampAnnotation := nic.Annotations[metalnetDeletionGracePeriodAnnotation]; hasDeletionGracePeriodTimestampAnnotation {
				requiresPatch = true
				delete(nic.Annotations, metalnetDeletionGracePeriodAnnotation)
			}
			// if changed, re-queue
			if requiresPatch {
				if err = r.Patch(ctx, nic, client.MergeFrom(baseNIC)); err != nil {
					return ctrl.Result{}, fmt.Errorf("error removing ok-to-delete information for nic: %w", err)
				}

				return ctrl.Result{Requeue: true}, nil
			}
		} else {
			// if not, log warning and
			log.V(1).Info("Machine UID not tracked, mark for deletion", "machineUID", machineUID)
			_, hasDeletionMarkAnnotation := nic.Annotations[metalnetDeletionMarkAnnotation]
			if hasDeletionMarkAnnotation {
				// check if grace period has been reached
				log.V(1).Info("Deletion mark annotation found, check deletion grace period timestamp", "machineUID", machineUID)
				gracePeriodTimestampValue := nic.Annotations[metalnetDeletionGracePeriodAnnotation]
				gracePeriodTimestamp, err := time.Parse(time.RFC3339, gracePeriodTimestampValue)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("error parsing deletion grace period timestamp: %w", err)
				}

				if time.Now().After(gracePeriodTimestamp) {
					log.V(1).Info("NIC deletion grace period reached, delete NIC", "machineUID", machineUID)
					// yes - delete
					if err = r.Delete(ctx, nic); err != nil {
						return ctrl.Result{}, fmt.Errorf("error deleting metalnet nic: %w", err)
					}

					return ctrl.Result{Requeue: true}, nil
				}

				return r.delete(ctx, log, nic)
			}

			log.V(1).Info("Deletion mark annotation not found, patch with deletion mark annotations", "machineUID", machineUID)
			baseNIC := nic.DeepCopy()
			if nic.Annotations == nil {
				nic.Annotations = make(map[string]string)
			}

			// add label "ok-to-delete"
			// add timestamp "grace-period"
			nic.Annotations[metalnetDeletionMarkAnnotation] = "true"
			nic.Annotations[metalnetDeletionGracePeriodAnnotation] = time.Now().Add(time.Hour * 24).Format(time.RFC3339)
			if err = r.Patch(ctx, nic, client.MergeFrom(baseNIC)); err != nil {
				return ctrl.Result{}, fmt.Errorf("error patching ok-to-delete information for nic: %w", err)
			}

			return ctrl.Result{}, nil
		}
	}

	network := &metalnetv1alpha1.Network{}
	networkKey := client.ObjectKey{Namespace: nic.Namespace, Name: nic.Spec.NetworkRef.Name}
	log.V(1).Info("Getting network", "NetworkKey", networkKey)
	if err := r.Get(ctx, networkKey, network); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("error getting network %s: %w", networkKey, err)
		}

		r.Eventf(nic, corev1.EventTypeWarning, "NetworkNotFound", "Network %s could not be found", networkKey.Name)
		if err := r.patchStatus(ctx, nic, func() {
			// Set controller status with pending state
			metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
				&nic.Status,
				r.ControllerID,
				string(metalnetv1alpha1.NetworkInterfaceStatePending),
				fmt.Sprintf("Network %s could not be found", networkKey.Name),
				nic.Generation,
				r.ControllerHash,
			)
			// Update overall status
			metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	isValid, err := r.isValidInterfaceSpec(&nic.Spec)
	if !isValid {
		if errPatch := r.patchStatus(ctx, nic, func() {
			// Set controller status with error state
			metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
				&nic.Status,
				r.ControllerID,
				string(metalnetv1alpha1.NetworkInterfaceStateError),
				fmt.Sprintf("Interface spec validation error: %v", err),
				nic.Generation,
				r.ControllerHash,
			)
			// Update overall status
			metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
		}); errPatch != nil {
			log.Error(errPatch, "Error patching network interface status")
		}
		return ctrl.Result{}, fmt.Errorf("interface spec validation error: %w", err)
	}

	vni := uint32(network.Spec.ID)
	log.V(1).Info("Got network", "NetworkKey", networkKey, "VNI", vni)

	log.V(1).Info("Applying interface")
	pciAddr, underlayRoute, isCreated, err := r.applyInterface(ctx, log, nic, vni)
	if err != nil {
		if patchErr := r.patchStatus(ctx, nic, func() {
			// Set controller status with error state
			metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
				&nic.Status,
				r.ControllerID,
				string(metalnetv1alpha1.NetworkInterfaceStateError),
				fmt.Sprintf("Error applying interface: %v", err),
				nic.Generation,
				r.ControllerHash,
			)
			// Update overall status
			metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
		}); patchErr != nil {
			log.Error(patchErr, "Error patching network interface status")
		}
		return ctrl.Result{}, fmt.Errorf("error applying interface: %w", err)
	}
	log.V(1).Info("Applied interface", "PCIAddress", pciAddr, "UnderlayRoute", underlayRoute)

	// The interface was just created via GRPC and object status state is already Ready.
	// So toggle the status state to reflect the "readiness" of the interface.
	if isCreated && nic.Status.GetState() == metalnetv1alpha1.NetworkInterfaceStateReady {
		// First set to pending
		if err := r.patchStatus(ctx, nic, func() {
			metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
				&nic.Status,
				r.ControllerID,
				string(metalnetv1alpha1.NetworkInterfaceStatePending),
				"Interface is being initialized",
				nic.Generation,
				r.ControllerHash,
			)
			metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
		}); err != nil {
			log.Error(err, "Error patching network interface status to pending")
		}

		// Then set to ready
		if err := r.patchStatus(ctx, nic, func() {
			metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
				&nic.Status,
				r.ControllerID,
				string(metalnetv1alpha1.NetworkInterfaceStateReady),
				"Interface is ready",
				nic.Generation,
				r.ControllerHash,
			)
			metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
		}); err != nil {
			log.Error(err, "Error patching network interface status to ready")
		}
	}
	var errs []error

	log.V(1).Info("Reconciling virtual ip")
	virtualIPErr := r.reconcileVirtualIP(ctx, log, nic)
	if virtualIPErr != nil {
		errs = append(errs, fmt.Errorf("error reconciling virtual ip: %w", virtualIPErr))
		log.Error(virtualIPErr, "Error reconciling virtual ip")
		r.Eventf(nic, corev1.EventTypeWarning, "ErrorReconcilingVirtualIP", "Error reconciling virtual ip: %v", err)
	} else {
		log.V(1).Info("Reconciled virtual ip")
	}

	log.V(1).Info("Reconciling nat ip")
	natIPErr := r.reconcileNATIP(ctx, log, nic, vni)
	if natIPErr != nil {
		errs = append(errs, fmt.Errorf("error reconciling nat ip: %w", natIPErr))
		log.Error(natIPErr, "Error reconciling nat ip")
		r.Eventf(nic, corev1.EventTypeWarning, "ErrorReconcilingNATIP", "Error reconciling nat ip: %v", err)
	} else {
		log.V(1).Info("Reconciled nat ip")
	}

	log.V(1).Info("Reconciling lb targets")
	lbTargetErr := r.reconcileLBTargets(ctx, log, vni, nic)
	if lbTargetErr != nil {
		errs = append(errs, fmt.Errorf("error reconciling lb target: %w", lbTargetErr))
		log.Error(lbTargetErr, "Error reconciling lb targets")
		r.Eventf(nic, corev1.EventTypeWarning, "ErrorReconcilingLBTargets", "Error reconciling lb targets: %v", err)
	} else {
		log.V(1).Info("Reconciled prefixes")
	}

	log.V(1).Info("Reconciling prefixes")
	prefixesErr := r.reconcilePrefixes(ctx, log, vni, nic)
	if prefixesErr != nil {
		errs = append(errs, fmt.Errorf("error reconciling prefixes: %w", prefixesErr))
		log.Error(prefixesErr, "Error reconciling prefixes")
		r.Eventf(nic, corev1.EventTypeWarning, "ErrorReconcilingPrefixes", "Error reconciling prefixes: %v", err)
	} else {
		log.V(1).Info("Reconciled prefixes")
	}

	log.V(1).Info("Reconciling firewall rules")
	fwruleErr := r.reconcileFirewallRules(ctx, log, nic)
	if fwruleErr != nil {
		errs = append(errs, fmt.Errorf("error reconciling firewall rules: %w", fwruleErr))
		log.Error(fwruleErr, "Error reconciling firewall rules")
		r.Eventf(nic, corev1.EventTypeWarning, "ErrorReconcilingFirewallRules", "Error reconciling firewall rules: %v", err)
	} else {
		log.V(1).Info("Reconciled firewall rules")
	}

	log.V(1).Info("Patching status")
	if err := r.patchStatus(ctx, nic, func() {
		// Update controller status with successful reconciliation
		metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
			&nic.Status,
			r.ControllerID,
			string(metalnetv1alpha1.NetworkInterfaceStateReady),
			"Network interface successfully reconciled",
			nic.Generation,
			r.ControllerHash,
		)

		// Update PCI address in status
		if r.BluefieldDetected {
			pciAddr.Bus = r.BluefieldHostDefaultBusAddr
			log.V(1).Info("Bluefield detected. Converting PCI Bus to the host PCI bus", "PCIAddress", pciAddr)
		}
		if r.TapDeviceMode {
			pciAddr.Device = strings.ReplaceAll(strings.ReplaceAll(pciAddr.Device, ":", ""), ".", "")
			nic.Status.TAPDevice = &metalnetv1alpha1.TAPDevice{
				Name: pciAddr.Device,
			}
		} else {
			nic.Status.PCIAddress = &metalnetv1alpha1.PCIAddress{
				Bus:      pciAddr.Bus,
				Domain:   pciAddr.Domain,
				Slot:     pciAddr.Device,
				Function: pciAddr.Function,
			}
		}

		// Copy other fields from spec to status based on reconciliation result
		if virtualIPErr == nil {
			nic.Status.VirtualIP = nic.Spec.VirtualIP
		}
		if natIPErr == nil {
			if nic.Spec.NAT != nil {
				nic.Status.NatIP = nic.Spec.NAT
			} else {
				nic.Status.NatIP = nil
			}
		} else {
			nic.Status.NatIP = nil
		}
		if prefixesErr == nil {
			nic.Status.Prefixes = nic.Spec.Prefixes
		}
		if lbTargetErr == nil {
			nic.Status.LoadBalancerTargets = nic.Spec.LoadBalancerTargets
		}

		// Update overall status
		metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("error patching status: %w", err)
	}

	if len(errs) > 0 {
		return ctrl.Result{}, fmt.Errorf("error applying network interface parts: %v", errs)
	}

	// Since it can not be ensured that we have not missed loadbalancer targets we ask for vni routes
	log.V(1).Info("Get routes for vni")
	if err := r.RouteUtil.GetRoutesForVni(ctx, metalbond.VNI(vni)); err != nil {
		return ctrl.Result{}, err
	}
	log.V(1).Info("Got routes for vni")

	return ctrl.Result{}, nil
}

func (r *NetworkInterfaceReconciler) reconcilePrefixes(ctx context.Context, log logr.Logger, vni uint32, nic *metalnetv1alpha1.NetworkInterface) error {
	log.V(1).Info("Listing alias prefixes")
	list, err := r.DPDK.ListPrefixes(ctx, string(nic.UID))
	if err != nil {
		return fmt.Errorf("error listing alias prefixes: %w", err)
	}

	dpdkPrefixes := sets.New[netip.Prefix]()
	for _, dpdkPrefix := range list.Items {
		dpdkPrefixes.Insert(dpdkPrefix.Spec.Prefix)
	}

	specPrefixes := sets.New[netip.Prefix]()
	for _, specPrefix := range nic.Spec.Prefixes {
		// only ipv4 is supported for now
		if specPrefix.Addr().Is4() {
			specPrefixes.Insert(specPrefix.Prefix)
		}
	}

	// Sort prefixes to have deterministic error event output
	allPrefixes := dpdkPrefixes.UnsortedList()
	sort.Slice(allPrefixes, func(i, j int) bool {
		return allPrefixes[i].String() < allPrefixes[j].String()
	})

	if dpdkPrefixes.Len() < specPrefixes.Len() {
		allPrefixes = specPrefixes.UnsortedList()
		sort.Slice(allPrefixes, func(i, j int) bool {
			return allPrefixes[i].String() < allPrefixes[j].String()
		})
	}
	var errs []error
	for _, prefix := range allPrefixes {
		if err := func() error {
			log := log.WithValues("Prefix", prefix)
			switch {
			case dpdkPrefixes.Has(prefix) && !specPrefixes.Has(prefix):
				log.V(1).Info("Delete prefix")
				underlayRoute, err := getUnderlayRouteFromPrefixesList(list.Items, prefix)
				if err != nil {
					return err
				}
				log.V(1).Info("Ensuring metalbond prefix route does not exist")
				if err := r.removePrefixRouteIfExists(ctx, vni, prefix, underlayRoute); err != nil {
					return err
				}
				log.V(1).Info("Ensured metalbond prefix route does not exist")

				log.V(1).Info("Ensuring dpdk prefix does not exist")
				if err := r.deleteDPDKPrefixIfExists(ctx, nic.UID, prefix); err != nil {
					return err
				}
				log.V(1).Info("Ensured dpdk prefix does not exist")
				return nil
			case specPrefixes.Has(prefix) && !dpdkPrefixes.Has(prefix):
				log.V(1).Info("Create prefix")

				log.V(1).Info("Creating dpdk prefix")
				var underlayRoute = &netip.Addr{}
				underlayRoute = nil
				for _, pfx := range nic.Status.Reservation.Prefixes {
					if pfx.Overlay == prefix.String() {
						ip := netip.MustParseAddr(pfx.Underlay)
						underlayRoute = &ip
						break
					}
				}

				if underlayRoute == nil {
					return errors.New("no underlay route for prefix found")
				}
				resPrefix, err := r.DPDK.CreatePrefix(ctx, &dpdk.Prefix{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec:       dpdk.PrefixSpec{Prefix: prefix, UnderlayRoute: underlayRoute},
				})
				if err != nil {
					if dpdkerrors.IsStatusErrorCode(err, dpdkerrors.ROUTE_EXISTS) {
						routes, err := r.DPDK.ListRoutes(ctx, vni)
						if err != nil {
							return err
						}

						// Handles the cleanup of an old route that conflicts with the current prefix during route reconciliation.
						for _, route := range routes.Items {
							if route.Spec.Prefix.String() == prefix.String() {
								log.V(1).Info(fmt.Sprintf("Cleanup old route that clashes with prefix: %s, vni: %d", prefix.String(), vni))
								// Try to delete old route
								if _, err := r.DPDK.DeleteRoute(
									ctx,
									vni,
									&prefix,
									dpdkerrors.Ignore(dpdkerrors.NO_VNI, dpdkerrors.ROUTE_NOT_FOUND, dpdkerrors.ROUTE_BAD_PORT),
								); err != nil {
									return fmt.Errorf("error deleting old existing route vni: %d, prefix: %s,  %w", vni, prefix.String(), err)
								}

								return errors.New("cleanup old route, force reconcile")
							}
						}
					}
					return err
				}
				log.V(1).Info("Ensured dpdk prefix exists")

				log.V(1).Info("Ensuring metalbond prefix route exists")
				if err := r.addPrefixRouteIfNotExists(ctx, vni, prefix, *resPrefix.Spec.UnderlayRoute); err != nil {
					return err
				}
				log.V(1).Info("Ensured metalbond prefix route exists")
				return nil
			default:
				log.V(1).Info("Update prefix")
				underlayRoute, err := getUnderlayRouteFromPrefixesList(list.Items, prefix)
				if err != nil {
					return err
				}
				log.V(1).Info("Ensuring metalbond prefix route exists")
				if err := r.addPrefixRouteIfNotExists(ctx, vni, prefix, underlayRoute); err != nil {
					return err
				}
				log.V(1).Info("Ensured metalbond prefix route exists")
				return nil
			}
		}(); err != nil {
			errs = append(errs, fmt.Errorf("[prefix %s] %w", prefix, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) reconciling prefix(es): %v", errs)
	}
	return nil
}

func getUnderlayRouteFromPrefixesList(list []dpdk.Prefix, searchPrefix netip.Prefix) (netip.Addr, error) {
	for _, dpdkPrefix := range list {
		if dpdkPrefix.Spec.Prefix.Addr() == searchPrefix.Addr() {
			return *dpdkPrefix.Spec.UnderlayRoute, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no underlayroute for lb prefix %v", searchPrefix.Addr())
}

func (r *NetworkInterfaceReconciler) reconcileLBTargets(ctx context.Context, log logr.Logger, vni uint32, nic *metalnetv1alpha1.NetworkInterface) error {
	log.V(1).Info("Listing lb targets")
	list, err := r.DPDK.ListLoadBalancerPrefixes(ctx, string(nic.UID))
	if err != nil {
		return fmt.Errorf("error listing lb targets: %w", err)
	}

	dpdkPrefixes := sets.New[netip.Prefix]()
	for _, dpdkPrefix := range list.Items {
		dpdkPrefixes.Insert(dpdkPrefix.Spec.Prefix)
	}

	specPrefixes := sets.New[netip.Prefix]()
	for _, specPrefix := range nic.Spec.LoadBalancerTargets {
		specPrefixes.Insert(specPrefix.Prefix)
	}

	// Sort prefixes to have deterministic error event output
	allPrefixes := dpdkPrefixes.UnsortedList()
	sort.Slice(allPrefixes, func(i, j int) bool {
		return allPrefixes[i].String() < allPrefixes[j].String()
	})

	if dpdkPrefixes.Len() < specPrefixes.Len() {
		allPrefixes = specPrefixes.UnsortedList()
		sort.Slice(allPrefixes, func(i, j int) bool {
			return allPrefixes[i].String() < allPrefixes[j].String()
		})
	}
	var errs []error
	for _, prefix := range allPrefixes {
		if err := func() error {
			log := log.WithValues("LB Target", prefix)
			switch {
			case dpdkPrefixes.Has(prefix) && !specPrefixes.Has(prefix):
				log.V(1).Info("Delete lb target")
				underlayRoute, err := getUnderlayRouteFromPrefixesList(list.Items, prefix)
				if err != nil {
					return err
				}
				log.V(1).Info("Ensuring metalbond prefix route does not exist")
				if err := r.removeLBTargetRouteIfExists(ctx, vni, prefix, underlayRoute); err != nil {
					return err
				}
				log.V(1).Info("Ensured metalbond prefix route does not exist")

				log.V(1).Info("Ensuring dpdk lb target does not exist")
				if err := r.deleteDPDKLBTargetIfExists(ctx, nic.UID, prefix); err != nil {
					return err
				}
				log.V(1).Info("Ensured dpdk lb target does not exist")
				return nil
			case specPrefixes.Has(prefix) && !dpdkPrefixes.Has(prefix):
				log.V(1).Info("Create lb target")

				log.V(1).Info("Creating dpdk lb target")
				var underlayRoute = &netip.Addr{}
				underlayRoute = nil
				for _, lbt := range nic.Status.Reservation.LoadBalancerTargets {
					if lbt.Overlay == prefix.String() {
						ip := netip.MustParseAddr(lbt.Underlay)
						underlayRoute = &ip
						break
					}
				}

				if underlayRoute == nil {
					return errors.New("no underlay route for lb prefix found")
				}
				resPrefix, err := r.DPDK.CreateLoadBalancerPrefix(ctx, &dpdk.LoadBalancerPrefix{
					LoadBalancerPrefixMeta: dpdk.LoadBalancerPrefixMeta{InterfaceID: string(nic.UID)},
					Spec:                   dpdk.LoadBalancerPrefixSpec{Prefix: prefix, UnderlayRoute: underlayRoute},
				})
				if err != nil {
					return err
				}
				log.V(1).Info("Ensured dpdk lb target exists")

				log.V(1).Info("Ensuring metalbond lb target route exists")
				if err := r.addLBTargetRouteIfNotExists(ctx, vni, prefix, *resPrefix.Spec.UnderlayRoute); err != nil {
					return err
				}
				log.V(1).Info("Ensured metalbond lb target route exists")
				return nil
			default:
				log.V(1).Info("Update lb target")
				underlayRoute, err := getUnderlayRouteFromPrefixesList(list.Items, prefix)
				if err != nil {
					return err
				}
				log.V(1).Info("Ensuring metalbond lb target route exists")

				dest := metalbond.Destination{
					Prefix: prefix,
				}
				underlayRouteAnnounced := r.RouteUtil.IsRouteAnnounced(ctx, metalbond.VNI(vni), dest, underlayRoute, pb.NextHopType_LOADBALANCER_TARGET, 0, 0)
				if !underlayRouteAnnounced {
					if err := r.addLBTargetRouteIfNotExists(ctx, vni, prefix, underlayRoute); err != nil {
						return err
					}
				} else {
					log.V(1).Info("Metalbond route already announced")
				}
				log.V(1).Info("Ensured metalbond lb target route exists")
				return nil
			}
		}(); err != nil {
			errs = append(errs, fmt.Errorf("[lb target %s] %w", prefix, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) reconciling lb target: %v", errs)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) reconcileFirewallRules(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) error {
	log.V(1).Info("Listing firewall rules")
	fwList, err := r.DPDK.ListFirewallRules(ctx, string(nic.UID))
	if err != nil {
		return fmt.Errorf("error listing firewall rule: %w", err)
	}
	list := fwList.Items

	dpdkFirewallRules := sets.New[string]()
	for _, dpdkFirewallRule := range list {
		dpdkFirewallRules.Insert(dpdkFirewallRule.Spec.RuleID)
	}

	specFirewallRules := sets.New[string]()
	for _, specFirewallRule := range nic.Spec.FirewallRules {
		specFirewallRules.Insert(string(specFirewallRule.FirewallRuleID))
	}

	// Sort FirewallRules to have deterministic error event output
	allFirewallRules := dpdkFirewallRules.UnsortedList()
	sort.Slice(allFirewallRules, func(i, j int) bool {
		return allFirewallRules[i] < allFirewallRules[j]
	})

	if dpdkFirewallRules.Len() < specFirewallRules.Len() {
		allFirewallRules = specFirewallRules.UnsortedList()
		sort.Slice(allFirewallRules, func(i, j int) bool {
			return allFirewallRules[i] < allFirewallRules[j]
		})
	}
	var errs []error
	var specFirewallRule metalnetv1alpha1.FirewallRule
	for _, fwRuleID := range allFirewallRules {
		if err := func() error {
			log := log.WithValues("FirewallRuleID", fwRuleID)
			switch {
			case dpdkFirewallRules.Has(fwRuleID) && !specFirewallRules.Has(fwRuleID):
				log.V(1).Info("Ensuring dpdk fwRuleID does not exist")
				if err := r.deleteDPDKfwRuleIDIfExists(ctx, string(nic.UID), fwRuleID); err != nil {
					return err
				}
				log.V(1).Info("Ensured dpdk fwRuleID does not exist")
				return nil
			case specFirewallRules.Has(fwRuleID) && !dpdkFirewallRules.Has(fwRuleID):
				for _, specFirewallRule = range nic.Spec.FirewallRules {
					if specFirewallRule.FirewallRuleID == types.UID(fwRuleID) {
						break
					}
				}
				log.V(1).Info("Creating dpdk fwRuleID")
				if err := r.createDPDKFwRule(ctx, nic, &specFirewallRule); err != nil {
					return err
				}
				log.V(1).Info("Ensured dpdk fwRuleID exists")
				return nil
			default:
				return nil
			}
		}(); err != nil {
			errs = append(errs, fmt.Errorf("[fwRuleID %s] %w", fwRuleID, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) reconciling fwRuleID(es): %v", errs)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) isValidMeteringParams(meteringParams *metalnetv1alpha1.MeteringParameters) (bool, error) {
	if meteringParams == nil {
		return true, nil
	}

	if meteringParams.TotalRate != nil && meteringParams.PublicRate != nil {
		if *meteringParams.TotalRate < *meteringParams.PublicRate {
			return false, fmt.Errorf("total rate cannot be less than public rate")
		}
	}

	return true, nil
}

func (r *NetworkInterfaceReconciler) getInterfaceMeteringParams(nic *metalnetv1alpha1.NetworkInterface) (*dpdk.MeteringParams, error) {
	meterParams := &dpdk.MeteringParams{
		TotalRate:  0,
		PublicRate: 0,
	}

	if nic.Spec.MeteringRate == nil {
		return meterParams, nil
	}

	if nic.Spec.MeteringRate.TotalRate != nil {
		meterParams.TotalRate = *nic.Spec.MeteringRate.TotalRate
	}

	if nic.Spec.MeteringRate.PublicRate != nil {
		meterParams.PublicRate = *nic.Spec.MeteringRate.PublicRate
	}

	return meterParams, nil
}

func (r *NetworkInterfaceReconciler) applyInterface(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, vni uint32) (*ghw.PCIAddress, netip.Addr, bool, error) {
	log.V(1).Info("Getting dpdk interface")
	hostName := ""

	iface, err := r.DPDK.GetInterface(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NOT_FOUND) {
			return nil, netip.Addr{}, false, fmt.Errorf("error getting dpdk interface: %w", err)
		}

		log.V(1).Info("DPDK interface does not yet exist, creating it")

		log.V(1).Info("Getting or claiming pci address")
		addr, err := r.NetFnsManager.GetOrClaim(nic.UID)
		if err != nil {
			return nil, netip.Addr{}, false, fmt.Errorf("error claiming address: %w", err)
		}
		log.V(1).Info("Got pci address", "Address", addr)

		log.V(1).Info("Converting to dpdk device")
		dpdkDevice, err := r.convertToDPDKDevice(*addr)
		if err != nil {
			return nil, netip.Addr{}, false, fmt.Errorf("error converting %s to dpdk device: %w", addr, err)
		}
		log.V(1).Info("Converted to dpdk device", "DPDKDevice", dpdkDevice)

		log.V(1).Info("Creating dpdk interface")

		primaryIpv4 := getNetworkInterfaceIP(corev1.IPv4Protocol, nic)
		primaryIpv6 := getNetworkInterfaceIP(corev1.IPv6Protocol, nic)

		meteringParams, err := r.getInterfaceMeteringParams(nic)
		if err != nil {
			return nil, netip.Addr{}, false, fmt.Errorf("error getting metering params: %w", err)
		}

		if nic.Spec.Hostname != nil {
			hostName = *nic.Spec.Hostname
		}

		underlayRoute := netip.MustParseAddr(nic.Status.Reservation.IPs[0].Underlay)
		iface, err := r.DPDK.CreateInterface(ctx, &dpdk.Interface{
			InterfaceMeta: dpdk.InterfaceMeta{ID: string(nic.UID)},
			Spec: dpdk.InterfaceSpec{
				VNI:           vni,
				Device:        dpdkDevice,
				IPv4:          &primaryIpv4,
				IPv6:          &primaryIpv6,
				UnderlayRoute: &underlayRoute,
				HostName: hostName,
				Metering: meteringParams,
			},
		})
		if err != nil {
			if dpdkerrors.IsStatusErrorCode(err, dpdkerrors.ROUTE_EXISTS) {
				routes, err := r.DPDK.ListRoutes(ctx, vni)
				if err != nil {
					return nil, netip.Addr{}, false, fmt.Errorf("error creating dpdk interface while list routes: %w", err)
				}

				// Handles the cleanup of an old route that conflicts with the current interface underlay ip during route reconciliation.
				for _, route := range routes.Items {
					if route.Spec.NextHop.IP.String() == underlayRoute.String() {
						log.V(1).Info(fmt.Sprintf("Cleanup old route that clashes with interface underlay ip: %s, vni: %d", underlayRoute.String(), vni))
						// Try to delete old route
						if _, err := r.DPDK.DeleteRoute(
							ctx,
							vni,
							route.Spec.Prefix,
							dpdkerrors.Ignore(dpdkerrors.NO_VNI, dpdkerrors.ROUTE_NOT_FOUND, dpdkerrors.ROUTE_BAD_PORT),
						); err != nil {
							return nil, netip.Addr{}, false, fmt.Errorf("error deleting old existing interface route vni: %d, prefix: %s,  %w", vni, underlayRoute.String(), err)
						}

						return nil, netip.Addr{}, false, errors.New("cleanup old route, force reconcile")
					}
				}
			}

			return nil, netip.Addr{}, false, errors.New("error creating dpdk interface: ROUTE_EXISTS")
		}

		log.V(1).Info("Adding interface routes if not exist")
		ips := getNetworkInterfaceIPs(nic)
		if err := r.addInterfaceRoutesIfNotExist(ctx, log, vni, ips, *iface.Spec.UnderlayRoute); err != nil {
			return nil, netip.Addr{}, false, err
		}
		log.V(1).Info("Added interface routes if not existed")
		return addr, *iface.Spec.UnderlayRoute, true, nil
	}

	log.V(1).Info("DPDK interface exists")

	log.V(1).Info("Getting pci device for uid")
	addr, err := r.NetFnsManager.Get(nic.UID)
	if err != nil {
		return nil, netip.Addr{}, false, fmt.Errorf("error getting pci address: %w", err)
	}
	log.V(1).Info("Got pci device for uid", "PCIDevice", addr)

	log.V(1).Info("Adding interface route if not exists")
	ips := getNetworkInterfaceIPs(nic)
	if err := r.addInterfaceRoutesIfNotExist(ctx, log, vni, ips, *iface.Spec.UnderlayRoute); err != nil {
		return nil, netip.Addr{}, false, err
	}
	log.V(1).Info("Added interface route if not existed")
	return addr, *iface.Spec.UnderlayRoute, false, nil
}

func (r *NetworkInterfaceReconciler) processTAPDeviceString(device string) (string, error) {
	cleanedDevice := strings.ReplaceAll(strings.ReplaceAll(device, ":", ""), ".", "")

	const prefix = "dtapvf_"
	if strings.HasPrefix(cleanedDevice, prefix) {
		numStr := cleanedDevice[len(prefix):]
		number, err := strconv.Atoi(numStr)
		if err != nil {
			return "", fmt.Errorf("failed to parse device number in %q: %w", cleanedDevice, err)
		}

		return fmt.Sprintf("net_tap%d", number+2), nil
	}

	return cleanedDevice, nil
}

func (r *NetworkInterfaceReconciler) convertToDPDKDevice(addr ghw.PCIAddress) (string, error) {
	if strings.Contains(addr.Device, "dtap") {
		return r.processTAPDeviceString(addr.Device)
	}
	pciFunction, err := strconv.ParseUint(addr.Function, 8, 64)
	if err != nil {
		return "", fmt.Errorf("error parsing address function %s: %w", addr.Function, err)
	}

	pciDevice, err := strconv.ParseUint(addr.Device, 16, 64)
	if err != nil {
		return "", fmt.Errorf("error parsing address device %s: %w", addr.Device, err)
	}
	pciFunction = pciDevice*8 + pciFunction

	pciDev, err := r.SysFS.PCIDevice(addr)
	if err != nil {
		// Calculate based on the offset parameter if sysfs not available

		if r.MultiportEswitchMode {
			return fmt.Sprintf("%s:%s:00.0_representor_c0pf0vf%d", addr.Domain, addr.Bus, pciFunction-uint64(r.PfToVfOffset)), nil
		} else {
			return fmt.Sprintf("%s:%s:00.0_representor_vf%d", addr.Domain, addr.Bus, pciFunction-uint64(r.PfToVfOffset)), nil
		}
	} else {
		physFn, err := pciDev.Physfn()
		if err != nil {
			return "", fmt.Errorf("error getting sysfs physfn: %w", err)
		}

		physFnAddr, err := physFn.Address()
		if err != nil {
			return "", fmt.Errorf("error getting physfn details: %w", err)
		}

		sriov, err := physFn.SRIOV()
		if err != nil {
			return "", fmt.Errorf("error getting sysfs sriov: %w", err)
		}
		if r.MultiportEswitchMode {
			return fmt.Sprintf("%s:%s:%s.0_representor_c0pf0vf%d", physFnAddr.Domain, physFnAddr.Bus, physFnAddr.Device, pciFunction-sriov.Offset), nil
		} else {
			return fmt.Sprintf("%s:%s:%s.0_representor_vf%d", physFnAddr.Domain, physFnAddr.Bus, physFnAddr.Device, pciFunction-sriov.Offset), nil
		}
	}
}

func (r *NetworkInterfaceReconciler) patchStatus(
	ctx context.Context,
	nic *metalnetv1alpha1.NetworkInterface,
	mutate func(),
) error {
	base := nic.DeepCopy()

	mutate()

	metalnetv1alpha1.SortIPs(base.Spec.IPs)
	metalnetv1alpha1.SortIPPrefixes(base.Spec.Prefixes)
	metalnetv1alpha1.SortIPPrefixes(base.Spec.LoadBalancerTargets)
	metalnetv1alpha1.SortIPFamilies(base.Spec.IPFamilies)
	metalnetv1alpha1.SortFirewallRuleSpecs(base.Spec.FirewallRules)
	metalnetv1alpha1.SortIPPrefixes(base.Status.Prefixes)
	metalnetv1alpha1.SortIPPrefixes(base.Status.LoadBalancerTargets)

	metalnetv1alpha1.SortIPs(nic.Spec.IPs)
	metalnetv1alpha1.SortIPPrefixes(nic.Spec.Prefixes)
	metalnetv1alpha1.SortIPPrefixes(nic.Spec.LoadBalancerTargets)
	metalnetv1alpha1.SortIPFamilies(nic.Spec.IPFamilies)
	metalnetv1alpha1.SortFirewallRuleSpecs(nic.Spec.FirewallRules)
	metalnetv1alpha1.SortIPPrefixes(nic.Status.Prefixes)
	metalnetv1alpha1.SortIPPrefixes(nic.Status.LoadBalancerTargets)

	// Create a merge patch with optimistic locking
	patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})

	if err := r.Status().Patch(ctx, nic, patch); err != nil {
		return fmt.Errorf("error patching status: %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) delete(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) (ctrl.Result, error) {
	log.V(1).Info("Delete")

	if !controllerutil.ContainsFinalizer(nic, r.finalizer()) {
		log.V(1).Info("No finalizer present, nothing to do")
		return ctrl.Result{}, nil
	}

	log.V(1).Info("Finalizer present, cleaning up")

	log.V(1).Info("Getting dpdk interface")
	dpdkIface, err := r.DPDK.GetInterface(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NOT_FOUND) {
			return ctrl.Result{}, fmt.Errorf("error getting dpdk interface: %w", err)
		}

		log.V(1).Info("Releasing device if existed")
		if err := r.releaseNetFnIfClaimExists(nic.UID); err != nil {
			return ctrl.Result{}, fmt.Errorf("error removing claim: %w", err)
		}
		log.V(1).Info("Released device if existed")

		log.V(1).Info("No dpdk interface, removing finalizer")
		// keep backward compatibility
		removed, err := r.removeFinalizer(ctx, log, nic, networkInterfaceFinalizer)
		if err != nil {
			return ctrl.Result{}, err
		}
		if removed {
			return ctrl.Result{Requeue: true}, nil
		}
		if _, err := r.removeFinalizer(ctx, log, nic, r.finalizer()); err != nil {
			return ctrl.Result{}, fmt.Errorf("error removing finalizer: %w", err)
		}
		log.V(1).Info("Removed finalizer")
		return ctrl.Result{}, nil
	}

	vni := dpdkIface.Spec.VNI
	underlayRoute := dpdkIface.Spec.UnderlayRoute
	log.V(1).Info("Got dpdk interface", "VNI", vni, "UnderlayRoute", underlayRoute)

	log.V(1).Info("Deleting prefixes")
	if err := r.deletePrefixes(ctx, log, nic, vni); err != nil {
		return ctrl.Result{}, fmt.Errorf("error deleting prefixes: %w", err)
	}
	log.V(1).Info("Deleted prefixes")

	log.V(1).Info("Deleting lb targets")
	if err := r.deleteLBTargets(ctx, log, nic, vni); err != nil {
		return ctrl.Result{}, fmt.Errorf("error deleting lb targets: %w", err)
	}
	log.V(1).Info("Deleted lb targets")

	log.V(1).Info("Deleting firewall rules")
	if err := r.deleteFirewallRules(ctx, log, nic); err != nil {
		return ctrl.Result{}, fmt.Errorf("error deleting firewall rules: %w", err)
	}
	log.V(1).Info("Deleted firewall rules")

	log.V(1).Info("Deleting nat ip")
	if err := r.deleteNATIP(ctx, log, nic, vni); err != nil {
		return ctrl.Result{}, fmt.Errorf("error deleting nat ip: %w", err)
	}
	log.V(1).Info("Deleted nat ip")

	log.V(1).Info("Deleting virtual ip")
	if err := r.deleteVirtualIP(ctx, log, nic); err != nil {
		return ctrl.Result{}, fmt.Errorf("error deleting virtual ip: %w", err)
	}
	log.V(1).Info("Deleted virtual ip")

	log.V(1).Info("Deleting interface")
	if err := r.deleteInterface(ctx, log, nic, vni, *underlayRoute); err != nil {
		return ctrl.Result{}, fmt.Errorf("error deleting underlay route: %w", err)
	}
	log.V(1).Info("Deleted interface")

	log.V(1).Info("Removing finalizer")
	// keep backward compatibility
	removed, err := r.removeFinalizer(ctx, log, nic, networkInterfaceFinalizer)
	if err != nil {
		return ctrl.Result{}, err
	}
	if removed {
		return ctrl.Result{Requeue: true}, nil
	}
	if _, err := r.removeFinalizer(ctx, log, nic, r.finalizer()); err != nil {
		return ctrl.Result{}, fmt.Errorf("error removing finalizer: %w", err)
	}
	log.V(1).Info("Removed finalizer")
	return ctrl.Result{}, nil
}

func (r *NetworkInterfaceReconciler) deleteLBTargets(
	ctx context.Context,
	log logr.Logger,
	nic *metalnetv1alpha1.NetworkInterface,
	vni uint32,
) error {
	log.V(1).Info("Listing lb targets")
	prefixes, err := r.DPDK.ListLoadBalancerPrefixes(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM) {
			return fmt.Errorf("error listing lb targets: %w", err)
		}

		log.V(1).Info("Interface already gone")
		return nil
	}

	var errs []error
	for _, prefixItem := range prefixes.Items {
		prefix := prefixItem.Spec.Prefix
		log := log.WithValues("LB Target", prefix)
		if err := func() error {
			log.V(1).Info("Removing lb targets route if exists")
			if err := r.removeLBTargetRouteIfExists(ctx, vni, prefix, *prefixItem.Spec.UnderlayRoute); err != nil {
				return err
			}
			log.V(1).Info("Removed lb target route if existed")

			log.V(1).Info("Removing dpdk lb target if exists")
			if err := r.deleteDPDKLBTargetIfExists(ctx, nic.UID, prefix); err != nil {
				return err
			}
			log.V(1).Info("Removed dpdk lb target if existed")
			return nil
		}(); err != nil {
			errs = append(errs, fmt.Errorf("[lb target %s] %w", prefix, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) deleting lb target(s): %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deletePrefixes(
	ctx context.Context,
	log logr.Logger,
	nic *metalnetv1alpha1.NetworkInterface,
	vni uint32,
) error {
	log.V(1).Info("Listing prefixes")
	prefixes, err := r.DPDK.ListPrefixes(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM) {
			return fmt.Errorf("error listing prefixes: %w", err)
		}

		log.V(1).Info("Interface already gone")
		return nil
	}

	var errs []error
	for _, prefix := range prefixes.Items {
		pfx := prefix.Spec.Prefix
		log := log.WithValues("Prefix", pfx)
		if err := func() error {
			log.V(1).Info("Removing prefix route if exists")
			if err := r.removePrefixRouteIfExists(ctx, vni, pfx, *prefix.Spec.UnderlayRoute); err != nil {
				return err
			}
			log.V(1).Info("Removed prefix route if existed")

			log.V(1).Info("Removing dpdk prefix if exists")
			if err := r.deleteDPDKPrefixIfExists(ctx, nic.UID, pfx); err != nil {
				return err
			}
			log.V(1).Info("Removed dpdk prefix if existed")
			return nil
		}(); err != nil {
			errs = append(errs, fmt.Errorf("[prefix %s] %w", pfx, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) deleting prefix(es): %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteFirewallRules(
	ctx context.Context,
	log logr.Logger,
	nic *metalnetv1alpha1.NetworkInterface,
) error {
	log.V(1).Info("Listing firewall rules")
	fwList, err := r.DPDK.ListFirewallRules(ctx, string(nic.UID))
	if err != nil {
		if !dpdkerrors.IsStatusErrorCode(err, dpdkerrors.NO_VM) {
			return fmt.Errorf("error listing firewall rules: %w", err)
		}
		log.V(1).Info("Interface already gone")
		return nil
	}

	var errs []error
	for _, fwRule := range fwList.Items {
		fwRuleID := fwRule.Spec.RuleID
		log := log.WithValues("Firewall Rule ID", fwRuleID)
		if err := func() error {
			log.V(1).Info("Removing dpdk firewall rule if exists")
			if err := r.deleteDPDKfwRuleIDIfExists(ctx, string(nic.UID), fwRuleID); err != nil {
				return err
			}
			log.V(1).Info("Removed dpdk firewall rule if existed")
			return nil
		}(); err != nil {
			errs = append(errs, fmt.Errorf("[firewall rule %s] %w", fwRuleID, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) deleting firewall rule(s): %w", err)
	}
	return nil
}

func (r *NetworkInterfaceReconciler) deleteInterface(
	ctx context.Context,
	log logr.Logger,
	nic *metalnetv1alpha1.NetworkInterface,
	vni uint32,
	underlayRoute netip.Addr,
) error {
	log.V(1).Info("Removing interface route if exists")
	ips := getNetworkInterfaceIPs(nic)
	if err := r.removeInterfaceRoutesIfExist(ctx, log, vni, ips, underlayRoute); err != nil {
		return err
	}
	log.V(1).Info("Removed interface route if existed")

	log.V(1).Info("Deleting dpdk interface if exists")
	if err := r.deleteDPDKInterfaceIfExists(ctx, nic.UID); err != nil {
		return err
	}
	log.V(1).Info("Deleted dpdk interface if existed")

	log.V(1).Info("Releasing device if existed")
	if err := r.releaseNetFnIfClaimExists(nic.UID); err != nil {
		return err
	}
	log.V(1).Info("Released device if existed")
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkInterfaceReconciler) SetupWithManager(mgr ctrl.Manager, metalnetCache cache.Cache) error {
	log := ctrl.Log.WithName("networkinterface").WithName("setup")
	ctx := ctrl.LoggerInto(context.TODO(), log)

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalnetv1alpha1.NetworkInterface{}, builder.WithPredicates(filterByNodePredicate(r.NodeName))).
		Watches(
			&metalnetv1alpha1.Network{},
			r.enqueueNetworkInterfacesReferencingNetwork(ctx, log),
		).
		Watches(
			&metalnetv1alpha1.LoadBalancer{},
			r.enqueueNetworkInterfacesReferencingLoadBalancer(ctx, log),
		).
		Complete(r)
}

func (r *NetworkInterfaceReconciler) enqueueNetworkInterfacesReferencingNetwork(ctx context.Context, log logr.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
		network := obj.(*metalnetv1alpha1.Network)
		nicList := &metalnetv1alpha1.NetworkInterfaceList{}
		if err := r.List(ctx, nicList,
			client.InNamespace(network.Namespace),
			client.MatchingFields{metalnetclient.NetworkInterfaceNetworkRefNameField: network.Name},
		); err != nil {
			log.Error(err, "Error listing network interfaces referencing network", "NetworkKey", client.ObjectKeyFromObject(network))
			return nil
		}

		reqs := make([]ctrl.Request, 0, len(nicList.Items))
		for _, nic := range nicList.Items {
			if isNetworkInterfaceAssignedToNode(&nic, r.NodeName) {
				reqs = append(reqs, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&nic)})
			}
		}
		return reqs
	})
}

// reconcileReservations handles the generation and management of IP reservations
// It returns (requeue, error) where requeue indicates if the reconciliation should be requeued
func (r *NetworkInterfaceReconciler) reconcileReservations(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface) (bool, error) {
	log.V(1).Info("Reconciling reservations")

	// Check if reservations need to be updated
	if nic.Status.Reservation == nil {
		log.V(1).Info("No existing reservations found, creating new ones")
	} else {
		// Check if spec has changed since last reservation
		needsUpdate := r.reservationsNeedUpdate(nic)
		if needsUpdate {
			log.V(1).Info("Spec has changed, updating reservations")
		} else {
			log.V(1).Info("Reservations are up to date")
			return false, nil
		}
	}

	// Create a new reservation
	reservation := &metalnetv1alpha1.NetworkInterfaceReservation{}
	var processingError error

	// Process all IPs in a single function that builds the entire reservation
	reservation, processingError = r.buildNetworkInterfaceReservation(nic)
	if processingError != nil {
		// If there's an error, update the status to show the error
		log.Error(processingError, "Failed to build network interface reservations")
		if updateErr := r.patchStatus(ctx, nic, func() {
			metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
				&nic.Status,
				r.ControllerID,
				string(metalnetv1alpha1.NetworkInterfaceStateError),
				fmt.Sprintf("Failed to generate IP reservations: %v", processingError),
				nic.Generation,
				r.ControllerHash,
			)
		}); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return false, processingError
	}

	// Update NetworkInterface status with the reservations
	if err := r.patchStatus(ctx, nic, func() {
		// Update the reservation in status
		nic.Status.Reservation = reservation

		// Set controller status to Ready
		metalnetv1alpha1.SetNetworkInterfaceControllerStatus(
			&nic.Status,
			r.ControllerID,
			string(metalnetv1alpha1.NetworkInterfaceStatePending),
			"IP reservations successfully generated",
			nic.Generation,
			r.ControllerHash,
		)

		// Update overall status
		metalnetv1alpha1.AggregateNetworkInterfaceStatus(&nic.Status, r.ReadyNeeded)
	}); err != nil {
		log.Error(err, "Failed to update NetworkInterface status with reservations")
		return false, err
	}

	log.V(1).Info("Successfully updated reservations, requeuing for main reconciliation")
	return true, nil
}

// reservationsNeedUpdate checks if the NetworkInterface spec has changed since the last reservation
func (r *NetworkInterfaceReconciler) reservationsNeedUpdate(nic *metalnetv1alpha1.NetworkInterface) bool {
	// If no reservation exists, update is needed
	if nic.Status.Reservation == nil {
		return true
	}

	// Check IP counts
	if len(nic.Spec.IPs) != len(nic.Status.Reservation.IPs) {
		return true
	}

	// Check for Virtual IP changes
	if (nic.Spec.VirtualIP != nil) && nic.Status.Reservation.VirtualIP == nil {
		return true
	}

	if nic.Spec.VirtualIP != nil &&
		(nic.Status.Reservation.VirtualIP == nil ||
			nic.Status.Reservation.VirtualIP.Overlay != nic.Spec.VirtualIP.String()) {
		return true
	}

	// Check for NAT IP changes
	natIPInSpec := nic.Spec.NAT != nil && nic.Spec.NAT.IP != nil
	natIPInStatus := nic.Status.Reservation.NatIP != nil

	if !natIPInSpec && natIPInStatus {
		return true
	}
	if natIPInSpec && !natIPInStatus {
		return true
	}
	if nic.Status.Reservation.NatIP != nil && nic.Status.Reservation.NatIP.Overlay != nic.Spec.NAT.IP.String() {
		return true
	}

	// Check LoadBalancer targets
	if len(nic.Spec.LoadBalancerTargets) != len(nic.Status.Reservation.LoadBalancerTargets) {
		return true
	}

	// Check for changes in the LoadBalancer targets
	specTargets := make(map[string]bool)
	for _, target := range nic.Spec.LoadBalancerTargets {
		specTargets[target.String()] = true
	}

	for _, target := range nic.Status.Reservation.LoadBalancerTargets {
		if !specTargets[target.Overlay] {
			return true
		}
	}

	// Check Prefixes
	if len(nic.Spec.Prefixes) != len(nic.Status.Reservation.Prefixes) {
		return true
	}

	// Check for changes in the Prefixes
	specPrefixes := make(map[string]bool)
	for _, prefix := range nic.Spec.Prefixes {
		specPrefixes[prefix.String()] = true
	}

	for _, prefix := range nic.Status.Reservation.Prefixes {
		if !specPrefixes[prefix.Overlay] {
			return true
		}
	}

	return false
}

// buildNetworkInterfaceReservation builds the complete reservation structure for all IP components
func (r *NetworkInterfaceReconciler) buildNetworkInterfaceReservation(nic *metalnetv1alpha1.NetworkInterface) (*metalnetv1alpha1.NetworkInterfaceReservation, error) {
	// Construct NetworkInterfaceReservation from Spec
	reservation := &metalnetv1alpha1.NetworkInterfaceReservation{
		IPs: make([]metalnetv1alpha1.IPReservation, 0, len(nic.Spec.IPs)),
	}

	// Get current reservation from the NetworkInterface status (if it exists)
	var currentReservation *metalnetv1alpha1.NetworkInterfaceReservation
	if nic.Status.Reservation != nil {
		currentReservation = nic.Status.Reservation
	}

	// Process all spec items at once and collect any errors
	var allErrors []error

	// Process IPs
	for _, ip := range nic.Spec.IPs {
		overlayIP := ip.String()

		// Check if this overlay IP already exists in the current reservation
		var underlayIP string
		var err error

		if currentReservation != nil {
			// Look for matching overlay IP in current reservation
			for _, existingIP := range currentReservation.IPs {
				if existingIP.Overlay == overlayIP {
					// Reuse existing underlay IP
					underlayIP = existingIP.Underlay
					break
				}
			}
		}

		// If no existing underlay IP was found, generate a new one
		if underlayIP == "" {
			underlayIP, err = r.generateUnderlayIP(ipv6manager.UNDERLAY_TYPE_NIC)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("failed to generate underlay IP for %s: %w", overlayIP, err))
				continue
			}
		}

		reservation.IPs = append(reservation.IPs, metalnetv1alpha1.IPReservation{
			Overlay:  overlayIP,
			Underlay: underlayIP,
		})
	}

	// Process Virtual IP if specified
	if nic.Spec.VirtualIP != nil && !nic.Spec.VirtualIP.IsZero() {
		overlayIP := nic.Spec.VirtualIP.String()

		// Check if this virtual IP already exists in the current reservation
		var underlayIP string
		var err error

		if currentReservation != nil && currentReservation.VirtualIP != nil &&
			currentReservation.VirtualIP.Overlay == overlayIP {
			// Reuse existing underlay IP
			underlayIP = currentReservation.VirtualIP.Underlay
		} else {
			// Generate new underlay IP
			underlayIP, err = r.generateUnderlayIP(ipv6manager.UNDERLAY_TYPE_VIP)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("failed to generate underlay IP for virtual IP %s: %w", overlayIP, err))
			}
		}

		if underlayIP != "" {
			reservation.VirtualIP = &metalnetv1alpha1.IPReservation{
				Overlay:  overlayIP,
				Underlay: underlayIP,
			}
		}
	}

	// Process NAT IPs if specified
	if nic.Spec.NAT != nil && nic.Spec.NAT.IP != nil && !nic.Spec.NAT.IP.IsZero() {
		overlayIP := nic.Spec.NAT.IP.String()

		// Check if this NAT IP already exists in the current reservation
		var underlayIP string
		var err error

		if currentReservation != nil && currentReservation.NatIP != nil &&
			currentReservation.NatIP.Overlay == overlayIP {
			// Reuse existing underlay IP
			underlayIP = currentReservation.NatIP.Underlay
		} else {
			// Generate new underlay IP
			underlayIP, err = r.generateUnderlayIP(ipv6manager.UNDERLAY_TYPE_NAT)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("failed to generate underlay IP for NAT IP %s: %w", overlayIP, err))
			}
		}

		if underlayIP != "" {
			reservation.NatIP = &metalnetv1alpha1.IPReservation{
				Overlay:  overlayIP,
				Underlay: underlayIP,
			}
		}
	}

	// Process LoadBalancerTargets
	if len(nic.Spec.LoadBalancerTargets) > 0 {
		reservation.LoadBalancerTargets = make([]metalnetv1alpha1.IPReservation, 0, len(nic.Spec.LoadBalancerTargets))

		for _, target := range nic.Spec.LoadBalancerTargets {
			overlayPrefix := target.String()

			// Check if this LoadBalancerTarget already exists in the current reservation
			var underlayIP string
			var err error

			if currentReservation != nil {
				// Look for matching overlay in current reservation
				for _, existingTarget := range currentReservation.LoadBalancerTargets {
					if existingTarget.Overlay == overlayPrefix {
						// Reuse existing underlay IP
						underlayIP = existingTarget.Underlay
						break
					}
				}
			}

			// If no existing underlay IP was found, generate a new one
			if underlayIP == "" {
				underlayIP, err = r.generateUnderlayIP(ipv6manager.UNDERLAY_TYPE_LBTARGET)
				if err != nil {
					allErrors = append(allErrors, fmt.Errorf("failed to generate underlay IP for LoadBalancer target %s: %w", overlayPrefix, err))
					continue
				}
			}

			reservation.LoadBalancerTargets = append(reservation.LoadBalancerTargets, metalnetv1alpha1.IPReservation{
				Overlay:  overlayPrefix,
				Underlay: underlayIP,
			})
		}
	}

	// Process Prefixes
	if len(nic.Spec.Prefixes) > 0 {
		reservation.Prefixes = make([]metalnetv1alpha1.IPReservation, 0, len(nic.Spec.Prefixes))

		for _, prefix := range nic.Spec.Prefixes {
			overlayPrefix := prefix.String()

			// Check if this prefix already exists in the current reservation
			var underlayIP string
			var err error

			if currentReservation != nil {
				// Look for matching overlay in current reservation
				for _, existingPrefix := range currentReservation.Prefixes {
					if existingPrefix.Overlay == overlayPrefix {
						// Reuse existing underlay IP
						underlayIP = existingPrefix.Underlay
						break
					}
				}
			}

			// If no existing underlay IP was found, generate a new one
			if underlayIP == "" {
				underlayIP, err = r.generateUnderlayIP(ipv6manager.UNDERLAY_TYPE_PREFIX)
				if err != nil {
					allErrors = append(allErrors, fmt.Errorf("failed to generate underlay IP for prefix %s: %w", overlayPrefix, err))
					continue
				}
			}

			reservation.Prefixes = append(reservation.Prefixes, metalnetv1alpha1.IPReservation{
				Overlay:  overlayPrefix,
				Underlay: underlayIP,
			})
		}
	}

	// If there were any errors, combine them and return
	if len(allErrors) > 0 {
		combinedError := fmt.Errorf("errors generating IP reservations: %v", allErrors)
		return nil, combinedError
	}

	return reservation, nil
}

// generateUnderlayIP generates an underlay IP for a given overlay IP
func (r *NetworkInterfaceReconciler) generateUnderlayIP(addressType uint8) (string, error) {
	// For IPv6, we use the IPv6Manager to generate a unique IPv6 address
	ipv6Manager := ipv6manager.GetInstance()
	return ipv6Manager.GenerateRandomIPv6(addressType)
}

func (r *NetworkInterfaceReconciler) enqueueNetworkInterfacesReferencingLoadBalancer(ctx context.Context, log logr.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
		loadBalancer := obj.(*metalnetv1alpha1.LoadBalancer)
		nicList := &metalnetv1alpha1.NetworkInterfaceList{}
		if err := r.List(ctx, nicList,
			client.InNamespace(loadBalancer.Namespace),
			client.MatchingFields{metalnetclient.LoadBalancerNetworkRefNameField: loadBalancer.Spec.NetworkRef.Name},
		); err != nil {
			log.Error(err, "Error listing network interfaces referencing loadbalancer", "NetworkKey", client.ObjectKeyFromObject(loadBalancer))
			return nil
		}

		reqs := make([]ctrl.Request, 0, len(nicList.Items))
		for _, nic := range nicList.Items {
			if isNetworkInterfaceAssignedToNode(&nic, r.NodeName) {
				reqs = append(reqs, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&nic)})
			}
		}
		return reqs
	})
}

func (r *NetworkInterfaceReconciler) finalizer() string {
	return fmt.Sprintf("%s-%s", networkInterfaceFinalizer, r.ControllerID)
}

func (r *NetworkInterfaceReconciler) removeFinalizer(ctx context.Context, log logr.Logger, nic *metalnetv1alpha1.NetworkInterface, finalizer string) (bool, error) {
	if controllerutil.ContainsFinalizer(nic, finalizer) {
		log.V(1).Info(fmt.Sprintf("finalizer '%s' present, cleaning up", finalizer))
		removed := controllerutil.RemoveFinalizer(nic, finalizer)
		if removed {
			if err := r.Update(ctx, nic); err != nil {
				return false, fmt.Errorf("error removing '%s' finalizer: %w", finalizer, err)
			}
			return true, nil
		} else {
			return false, nil
		}
	}

	return false, nil
}
