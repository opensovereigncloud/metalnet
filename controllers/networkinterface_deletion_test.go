// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"net/netip"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	"github.com/jaypipes/ghw"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("NetworkInterfaceReconciler - Deletion and Cleanup", func() {
	var (
		ctx           context.Context
		ns            *corev1.Namespace
		network       *metalnetv1alpha1.Network
		reconciler    *NetworkInterfaceReconciler
		dpdkMock      *mocks.DPDKClientMock
		routeUtilMock *mocks.RouteUtilMock
		netFnsMock    *mocks.NetFnsManagerMock
	)

	BeforeEach(func() {
		ctx, ns, network, reconciler, dpdkMock, routeUtilMock, netFnsMock = setupNetworkInterfaceTest()
	})

	AfterEach(func() {
		cleanupNetworkInterfaceTest(ctx, ns, dpdkMock, routeUtilMock, netFnsMock)
	})

	Context("DPDK Deletion Error Propagation", func() {
		It("should propagate route withdrawal errors", func() {
			// Create interface with VirtualIP
			virtualIP := netip.MustParseAddr("10.100.1.2")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-withdraw-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.21")},
					},
					VirtualIP: &metalnetv1alpha1.IP{Addr: virtualIP},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Now remove VirtualIP and set withdrawal error
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			nic.Spec.VirtualIP = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("route withdrawal failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("route withdrawal failed"))
		})

		It("should propagate DeleteVirtualIP errors", func() {
			// Create interface with VirtualIP
			virtualIP := netip.MustParseAddr("10.100.1.3")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-vip-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.22")},
					},
					VirtualIP: &metalnetv1alpha1.IP{Addr: virtualIP},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Remove VirtualIP and inject delete error
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			nic.Spec.VirtualIP = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			dpdkMock.SetDeleteVirtualIPError(fmt.Errorf("DPDK delete VIP failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete VIP failed"))
		})

		It("should propagate DeletePrefix errors", func() {
			// Create interface with Prefix
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-prefix-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.23")},
					},
					Prefixes: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.10.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Configure mock to return the created prefix in list response
			underlayRoute := netip.MustParseAddr("192.168.1.100")
			dpdkMock.SetListPrefixesResponse([]dpdk.Prefix{
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.10.0.0/24"),
						UnderlayRoute: &underlayRoute,
					},
				},
			})

			// Remove Prefix and inject delete error
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			nic.Spec.Prefixes = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			dpdkMock.SetDeletePrefixError(fmt.Errorf("DPDK delete prefix failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete prefix failed"))
		})

		It("should propagate DeleteLoadBalancerPrefix errors", func() {
			// Create interface with LoadBalancerTarget
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-lb-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.24")},
					},
					LoadBalancerTargets: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.20.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Configure mock to return the created LB prefix in list response
			underlayRoute := netip.MustParseAddr("192.168.1.101")
			dpdkMock.SetListLoadBalancerPrefixesResponse([]dpdk.Prefix{
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.20.0.0/24"),
						UnderlayRoute: &underlayRoute,
					},
				},
			})

			// Remove LB target and inject delete error
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			nic.Spec.LoadBalancerTargets = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			dpdkMock.SetDeleteLoadBalancerPrefixError(fmt.Errorf("DPDK delete LB prefix failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete LB prefix failed"))
		})

		It("should propagate DeleteNat errors", func() {
			// Create interface with NAT
			natIP := netip.MustParseAddr("203.0.113.20")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-nat-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.25")},
					},
					NAT: &metalnetv1alpha1.NATDetails{
						IP:      &metalnetv1alpha1.IP{Addr: natIP},
						Port:    30000,
						EndPort: 30100,
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Remove NAT and inject delete error
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			nic.Spec.NAT = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			dpdkMock.SetDeleteNatError(fmt.Errorf("DPDK delete NAT failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete NAT failed"))
		})

		It("should propagate DeleteInterface errors during cleanup", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-iface-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.26")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Delete the interface and inject delete error
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			dpdkMock.SetDeleteInterfaceError(fmt.Errorf("DPDK delete interface failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete interface failed"))
		})
	})

	Context("RouteUtil Withdrawal Error Propagation", func() {
		It("should propagate removeInterfaceRouteIfExists errors", func() {
			// Create and reconcile interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-remove-route-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.50")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Mark for deletion
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject route withdrawal error (not NextHopNotFoundError)
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("route withdrawal failed"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("route withdrawal failed"))
		})

		It("should propagate removePrefixRouteIfExists errors", func() {
			// Create interface with prefix
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-remove-prefix-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.51")},
					},
					Prefixes: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.12.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Mark for deletion (triggers full cleanup including prefix routes)
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject route withdrawal error
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("prefix route withdrawal failed"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("prefix route withdrawal failed"))
		})

		It("should propagate removeLBTargetRouteIfExists errors", func() {
			// Create interface with LoadBalancerTarget
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-remove-lb-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.52")},
					},
					LoadBalancerTargets: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.22.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Mark for deletion (triggers full cleanup including LB target routes)
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject route withdrawal error
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("LB target route withdrawal failed"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("LB target route withdrawal failed"))
		})

		// Removed IPv6 test - requires controller-level IPv6 configuration
	})

	Context("NetFns Manager Error Propagation", func() {
		It("should propagate releaseNetFnIfClaimExists errors", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-netfns-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.60")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Mark for deletion
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject NetFns release error (not ErrClaimNotFound)
			netFnsMock.SetReleaseError(fmt.Errorf("NetFns release failed"))

			// Reconcile should fail during cleanup
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("NetFns release failed"))
		})
	})

	Context("Firewall Deletion Error Handling", func() {
		It("should handle ListFirewallRules error during deletion", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-fw-list-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.217")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Setup NetFns mock to simulate PCI address already claimed
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Mark for deletion
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject ListFirewallRules error (not NO_VM, which is ignored)
			dpdkMock.SetListFirewallRulesError(fmt.Errorf("firewall service unavailable"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error listing firewall rules"))
		})

		It("should handle NO_VM error gracefully during firewall listing", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-fw-no-vm",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.201")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Mark for deletion
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject NO_VM error (should be ignored - interface already gone)
			noVmErr := dpdkerrors.NewStatusError(dpdkerrors.NO_VM, "interface not found")
			dpdkMock.SetListFirewallRulesError(noVmErr)

			// Reconcile should succeed (NO_VM is ignored)
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle DeleteFirewallRule error during deletion", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-fw-delete-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.202")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Mark for deletion
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Setup firewall rules to be deleted
			dpdkMock.SetListFirewallRulesResponse([]dpdk.FirewallRule{
				{
					FirewallRuleMeta: dpdk.FirewallRuleMeta{
						InterfaceID: string(nic.UID),
					},
					Spec: dpdk.FirewallRuleSpec{
						RuleID: "test-rule-1",
					},
				},
				{
					FirewallRuleMeta: dpdk.FirewallRuleMeta{
						InterfaceID: string(nic.UID),
					},
					Spec: dpdk.FirewallRuleSpec{
						RuleID: "test-rule-2",
					},
				},
			})

			// Inject DeleteFirewallRule error (not NO_VM or NOT_FOUND, which are ignored)
			dpdkMock.SetDeleteFirewallRuleError(fmt.Errorf("firewall rule deletion failed"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error deleting firewall rule"))
		})

		It("should successfully delete firewall rules when no errors", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-fw-delete-success",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.203")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Mark for deletion
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Setup firewall rules to be deleted
			dpdkMock.SetListFirewallRulesResponse([]dpdk.FirewallRule{
				{
					FirewallRuleMeta: dpdk.FirewallRuleMeta{
						InterfaceID: string(nic.UID),
					},
					Spec: dpdk.FirewallRuleSpec{
						RuleID: "test-rule-success",
					},
				},
			})

			// Reconcile should succeed and delete firewall rules
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify interface was fully cleaned up
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})
	})

	Context("Deletion Edge Cases", func() {
		It("should gracefully delete interface when DPDK state is missing", func() {
			// Create interface
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-missing-dpdk",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.90")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile to add finalizer and create interface
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Simulate DPDK state loss by removing interface from stateful mock
			dpdkMock.RemoveCreatedInterface(string(nic.UID))

			// Delete the interface
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Reconcile deletion - should handle NOT_FOUND gracefully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify interface was removed from k8s (finalizer removed despite DPDK NOT_FOUND)
			err := k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))

			// Should not try to delete non-existent interface
			Expect(dpdkMock.DeleteInterfaceCallCount()).To(Equal(0))

			// Should still release NetFns
			Expect(netFnsMock.ReleaseCallCount()).To(BeNumerically(">=", 1))
		})

		It("should remove finalizer even when route withdrawal fails during delete", func() {
			// Create interface with prefix
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-route-fail",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.91")},
					},
					Prefixes: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.100.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup status with prefix reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				IPs: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.0.0.91", Underlay: "192.168.1.91"},
				},
				Prefixes: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.100.0.0/24", Underlay: "192.168.1.92"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Reconcile to create interface
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Configure route withdrawal to fail
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("route withdrawal failed"))

			// Delete the interface
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Reconcile deletion - should fail due to route withdrawal error
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("route withdrawal failed"))

			// Clear the error to allow cleanup to complete
			routeUtilMock.SetWithdrawRouteError(nil)

			// Reconcile again - should succeed now
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify interface was removed from k8s
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should handle VirtualIP cleanup error during delete", func() {
			// Create interface with VirtualIP
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-vip-fail",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.92")},
					},
					VirtualIP: &metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("10.200.0.1"),
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup status with VirtualIP reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				IPs: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.0.0.92", Underlay: "192.168.1.92"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Reconcile to create interface
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Configure VirtualIP to exist in DPDK
			vipAddr := netip.MustParseAddr("10.200.0.1")
			underlayRoute := netip.MustParseAddr("192.168.1.92")
			dpdkMock.SetGetVirtualIPResponse(&dpdk.VirtualIP{
				Spec: dpdk.VirtualIPSpec{
					IP:            &vipAddr,
					UnderlayRoute: &underlayRoute,
				},
			}, nil)

			// Configure route withdrawal to fail for VirtualIP cleanup
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("VIP route withdrawal failed"))

			// Delete the interface
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Reconcile deletion - should fail due to VIP route withdrawal error
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("VIP route withdrawal failed"))

			// Clear the error
			routeUtilMock.SetWithdrawRouteError(nil)

			// Reconcile again - should succeed
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify interface was removed from k8s
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})
	})

	Context("Orphaned Resource Cleanup", func() {
		It("should handle orphaned DPDK prefix when route withdrawal fails during full deletion", func() {
			// Create interface with prefix
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-orphaned-prefix",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.204")},
					},
					Prefixes: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.0.204.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Verify prefix was created during reconciliation
			Expect(dpdkMock.CreatePrefixCallCount()).To(BeNumerically(">=", 1))
			initialDeleteCallCount := dpdkMock.DeletePrefixCallCount()

			// Configure mock to return the prefix when ListPrefixes is called during deletion
			underlayRoute := netip.MustParseAddr("192.168.1.204")
			dpdkMock.SetListPrefixesResponse([]dpdk.Prefix{
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.0.204.0/24"),
						UnderlayRoute: &underlayRoute,
					},
				},
			})

			// Mark for deletion (set deletion timestamp)
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject WithdrawRoute error for prefix route
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("BGP route withdrawal failed"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("BGP route withdrawal failed"))

			// Verify prefix is NOT deleted from DPDK (route must be withdrawn first)
			// DeletePrefix should not have been called yet
			Expect(dpdkMock.DeletePrefixCallCount()).To(Equal(initialDeleteCallCount), "Prefix should not be deleted when route withdrawal fails")

			// Clear the error
			routeUtilMock.SetWithdrawRouteError(nil)

			// Reconcile again and verify cleanup completes
			err = reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify interface was fully cleaned up
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))

			// Verify prefix was eventually deleted
			Expect(dpdkMock.DeletePrefixCallCount()).To(BeNumerically(">", initialDeleteCallCount))
		})

		It("should handle orphaned DPDK LB target when route withdrawal fails during full deletion", func() {
			// Create LoadBalancer
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-orphaned",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					LBtype:     "Public",
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("203.0.113.100"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{
							Protocol: "TCP",
							Port:     80,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Create interface with LoadBalancer target (as IPPrefix)
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-orphaned-lb",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.205")},
					},
					LoadBalancerTargets: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.0.205.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Verify LB target was created during reconciliation
			Expect(dpdkMock.CreateLoadBalancerPrefixCallCount()).To(BeNumerically(">=", 1))
			initialDeleteCallCount := dpdkMock.DeleteLoadBalancerPrefixCallCount()

			// Configure mock to return the LB target when ListLoadBalancerPrefixes is called during deletion
			underlayRoute := netip.MustParseAddr("192.168.1.205")
			dpdkMock.SetListLoadBalancerPrefixesResponse([]dpdk.Prefix{
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.0.205.0/24"),
						UnderlayRoute: &underlayRoute,
					},
				},
			})

			// Mark for deletion (set deletion timestamp)
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())

			// Inject WithdrawRoute error for LB target route
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("route server unreachable"))

			// Reconcile should fail during deletion
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("route server unreachable"))

			// Verify LB target is NOT deleted from DPDK
			// DeleteLoadBalancerPrefix should not have been called yet
			Expect(dpdkMock.DeleteLoadBalancerPrefixCallCount()).To(Equal(initialDeleteCallCount), "LB target should not be deleted when route withdrawal fails")

			// Clear error and reconcile again
			routeUtilMock.SetWithdrawRouteError(nil)

			// Verify cleanup completes
			err = reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify interface was fully cleaned up
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))

			// Verify LB target was eventually deleted
			Expect(dpdkMock.DeleteLoadBalancerPrefixCallCount()).To(BeNumerically(">", initialDeleteCallCount))
		})
	})
})
