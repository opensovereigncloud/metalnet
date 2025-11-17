// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"net/netip"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	"github.com/jaypipes/ghw"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("NetworkInterfaceReconciler - Prefix and LoadBalancer Reconciliation", func() {
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

	Context("Prefix Reconciliation", func() {
		var nic *metalnetv1alpha1.NetworkInterface

		BeforeEach(func() {
			nic = &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-prefixes",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.10")},
					},
				},
			}
		})

		DescribeTable("Prefix reconciliation with Union fix validation",
			func(dpdkPrefixStrs, specPrefixStrs []string, expectedCreates, expectedDeletes int) {
				// Setup spec prefixes
				nic.Spec.Prefixes = make([]metalnetv1alpha1.IPPrefix, len(specPrefixStrs))
				for i, ps := range specPrefixStrs {
					nic.Spec.Prefixes[i] = metalnetv1alpha1.IPPrefix{
						Prefix: netip.MustParsePrefix(ps),
					}
				}

				// Create NetworkInterface
				Expect(k8sClient.Create(ctx, nic)).To(Succeed())

				// Setup NetFns mock to simulate PCI address already claimed for this specific UID
				netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

				// Don't set GetInterfaceResponse - let stateful mock handle it
				// (interface will be created on first reconcile and stored in createdInterfaces map)

				// Setup ListPrefixes response
				dpdkPrefixes := make([]dpdk.Prefix, len(dpdkPrefixStrs))
				for i, ps := range dpdkPrefixStrs {
					underlayRoute := netip.MustParseAddr("192.168.1.1")
					dpdkPrefixes[i] = dpdk.Prefix{
						PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
						Spec: dpdk.PrefixSpec{
							Prefix:        netip.MustParsePrefix(ps),
							UnderlayRoute: &underlayRoute,
						},
					}
				}
				dpdkMock.SetListPrefixesResponse(dpdkPrefixes)

				// Setup status with underlay routes for CREATE operations
				nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
					Prefixes: make([]metalnetv1alpha1.IPReservation, len(specPrefixStrs)),
				}
				for i, ps := range specPrefixStrs {
					nic.Status.Reservation.Prefixes[i] = metalnetv1alpha1.IPReservation{
						Overlay:  ps,
						Underlay: "192.168.1.2",
					}
				}
				Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

				// Reconcile until complete (handles reservation updates + DPDK sync)
				Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

				// Assert DPDK calls - THIS VALIDATES THE UNION FIX
				Expect(dpdkMock.CreatePrefixCallCount()).To(Equal(expectedCreates),
					"Should CREATE %d prefixes (Union fix validation)", expectedCreates)
				Expect(dpdkMock.DeletePrefixCallCount()).To(Equal(expectedDeletes),
					"Should DELETE %d prefixes (Union fix validation)", expectedDeletes)
			},
			Entry("No prefixes in either set",
				[]string{}, []string{}, 0, 0),
			Entry("Add new prefixes (empty DPDK, populated spec)",
				[]string{},
				[]string{"10.0.1.0/24", "10.0.2.0/24"},
				2, 0),
			Entry("Remove all prefixes (populated DPDK, empty spec)",
				[]string{"10.0.1.0/24", "10.0.2.0/24"},
				[]string{},
				0, 2),
			Entry("Identical sets (no changes)",
				[]string{"10.0.1.0/24", "10.0.2.0/24"},
				[]string{"10.0.1.0/24", "10.0.2.0/24"},
				0, 0),
			Entry("CRITICAL: DPDK=3, Spec=4 (TODO scenario) - validates Union fix",
				[]string{"10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"},
				[]string{"10.0.1.0/24", "10.0.2.0/24", "10.0.4.0/24", "10.0.5.0/24"},
				2, 1), // Should CREATE 2 (10.0.4.0/24, 10.0.5.0/24), DELETE 1 (10.0.3.0/24)
			Entry("CRITICAL: DPDK=4, Spec=3 (reverse scenario) - validates Union fix",
				[]string{"10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24"},
				[]string{"10.0.1.0/24", "10.0.2.0/24", "10.0.5.0/24"},
				1, 2), // Should CREATE 1 (10.0.5.0/24), DELETE 2 (10.0.3.0/24, 10.0.4.0/24)
			Entry("CRITICAL: Disjoint sets - validates Union fix",
				[]string{"10.0.1.0/24", "10.0.2.0/24"},
				[]string{"10.0.3.0/24", "10.0.4.0/24", "10.0.5.0/24"},
				3, 2), // Should CREATE 3, DELETE 2
		)

		It("should handle partial prefix set overlap", func() {
			// DPDK has: A, B, C
			// Spec has:  A, B, D
			// Expected: CREATE D, DELETE C, keep A and B

			nic.Spec.Prefixes = []metalnetv1alpha1.IPPrefix{
				{Prefix: netip.MustParsePrefix("10.0.1.0/24")}, // A
				{Prefix: netip.MustParsePrefix("10.0.2.0/24")}, // B
				{Prefix: netip.MustParsePrefix("10.0.4.0/24")}, // D (new)
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Don't set GetInterfaceResponse - let stateful mock handle it
			// (interface will be created on first reconcile and stored in createdInterfaces map)

			underlayRoute := netip.MustParseAddr("192.168.1.1")
			dpdkMock.SetListPrefixesResponse([]dpdk.Prefix{
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.0.1.0/24"), // A
						UnderlayRoute: &underlayRoute,
					},
				},
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.0.2.0/24"), // B
						UnderlayRoute: &underlayRoute,
					},
				},
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.0.3.0/24"), // C (to be deleted)
						UnderlayRoute: &underlayRoute,
					},
				},
			})

			// Setup status
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				Prefixes: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.0.1.0/24", Underlay: "192.168.1.2"},
					{Overlay: "10.0.2.0/24", Underlay: "192.168.1.2"},
					{Overlay: "10.0.4.0/24", Underlay: "192.168.1.2"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Reconcile until done
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify actions
			Expect(dpdkMock.CreatePrefixCallCount()).To(Equal(1)) // D
			Expect(dpdkMock.DeletePrefixCallCount()).To(Equal(1)) // C

			// Verify the deleted prefix was C
			deletedPrefixes := dpdkMock.GetDeletePrefixArgs()
			Expect(deletedPrefixes).To(HaveLen(1))
			Expect(deletedPrefixes[0].String()).To(Equal("10.0.3.0/24"))
		})
	})

	Context("LoadBalancer Target Reconciliation", func() {
		var nic *metalnetv1alpha1.NetworkInterface

		BeforeEach(func() {
			nic = &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-lb",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.20")},
					},
				},
			}
		})

		DescribeTable("LB Target reconciliation with Union fix validation",
			func(dpdkLBPrefixStrs, specLBPrefixStrs []string, expectedCreates, expectedDeletes int) {
				// Setup spec LB targets
				nic.Spec.LoadBalancerTargets = make([]metalnetv1alpha1.IPPrefix, len(specLBPrefixStrs))
				for i, ps := range specLBPrefixStrs {
					nic.Spec.LoadBalancerTargets[i] = metalnetv1alpha1.IPPrefix{
						Prefix: netip.MustParsePrefix(ps),
					}
				}

				Expect(k8sClient.Create(ctx, nic)).To(Succeed())

				// Setup NetFns mock to simulate PCI address already claimed for this specific UID
				netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

				// Don't set GetInterfaceResponse - let stateful mock handle it
				// (interface will be created on first reconcile and stored in createdInterfaces map)

				// Setup ListLoadBalancerPrefixes response
				dpdkLBPrefixes := make([]dpdk.Prefix, len(dpdkLBPrefixStrs))
				for i, ps := range dpdkLBPrefixStrs {
					underlayRoute := netip.MustParseAddr("192.168.2.1")
					dpdkLBPrefixes[i] = dpdk.Prefix{
						Spec: dpdk.PrefixSpec{
							Prefix:        netip.MustParsePrefix(ps),
							UnderlayRoute: &underlayRoute,
						},
					}
				}
				dpdkMock.SetListLoadBalancerPrefixesResponse(dpdkLBPrefixes)

				// Setup status with underlay routes
				nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
					LoadBalancerTargets: make([]metalnetv1alpha1.IPReservation, len(specLBPrefixStrs)),
				}
				for i, ps := range specLBPrefixStrs {
					nic.Status.Reservation.LoadBalancerTargets[i] = metalnetv1alpha1.IPReservation{
						Overlay:  ps,
						Underlay: "192.168.2.2",
					}
				}
				Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

				// Reconcile until complete (handles reservation updates + DPDK sync)
				Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

				// Assert DPDK calls - THIS VALIDATES THE UNION FIX FOR LB TARGETS
				Expect(dpdkMock.CreateLoadBalancerPrefixCallCount()).To(Equal(expectedCreates),
					"Should CREATE %d LB targets (Union fix validation)", expectedCreates)
				Expect(dpdkMock.DeleteLoadBalancerPrefixCallCount()).To(Equal(expectedDeletes),
					"Should DELETE %d LB targets (Union fix validation)", expectedDeletes)
			},
			Entry("No LB targets in either set",
				[]string{}, []string{}, 0, 0),
			Entry("Add new LB targets",
				[]string{},
				[]string{"10.1.1.0/24", "10.1.2.0/24"},
				2, 0),
			Entry("Remove all LB targets",
				[]string{"10.1.1.0/24", "10.1.2.0/24"},
				[]string{},
				0, 2),
			Entry("CRITICAL: DPDK=3, Spec=4 (TODO scenario) - validates Union fix",
				[]string{"10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"},
				[]string{"10.1.1.0/24", "10.1.2.0/24", "10.1.4.0/24", "10.1.5.0/24"},
				2, 1),
			Entry("CRITICAL: DPDK=4, Spec=3 (reverse) - validates Union fix",
				[]string{"10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24", "10.1.4.0/24"},
				[]string{"10.1.1.0/24", "10.1.2.0/24", "10.1.5.0/24"},
				1, 2),
			Entry("CRITICAL: Disjoint LB target sets - validates Union fix",
				[]string{"10.1.1.0/24", "10.1.2.0/24"},
				[]string{"10.1.3.0/24", "10.1.4.0/24"},
				2, 2),
		)
	})

	Context("Prefix and LoadBalancer Error Paths", func() {
		It("should handle ListPrefixes error during prefix reconciliation", func() {
			// Create interface with prefix
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-list-prefixes-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.100")},
					},
					Prefixes: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.100.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				Prefixes: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.100.0.0/24", Underlay: "192.168.1.100"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Inject ListPrefixes error
			dpdkMock.SetListPrefixesError(fmt.Errorf("DPDK service unavailable"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error listing alias prefixes"))
		})

		It("should handle CreateLoadBalancerPrefix error during LB target creation", func() {
			// Create interface with LoadBalancer target
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-create-lb-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.101")},
					},
					LoadBalancerTargets: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.101.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				LoadBalancerTargets: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.101.0.0/24", Underlay: "192.168.1.101"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Inject CreateLoadBalancerPrefix error
			dpdkMock.SetCreateLoadBalancerPrefixError(fmt.Errorf("DPDK LB resource exhausted"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK LB resource exhausted"))
		})

		It("should handle DeleteLoadBalancerPrefix error during LB target deletion", func() {
			// Create interface with LoadBalancer target
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-delete-lb-prefix-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.102")},
					},
					LoadBalancerTargets: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.102.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				LoadBalancerTargets: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.102.0.0/24", Underlay: "192.168.1.102"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// First reconcile - create successfully
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Configure mock to return the created LB prefix
			underlayRoute := netip.MustParseAddr("192.168.1.102")
			dpdkMock.SetListLoadBalancerPrefixesResponse([]dpdk.Prefix{
				{
					PrefixMeta: dpdk.PrefixMeta{InterfaceID: string(nic.UID)},
					Spec: dpdk.PrefixSpec{
						Prefix:        netip.MustParsePrefix("10.102.0.0/24"),
						UnderlayRoute: &underlayRoute,
					},
				},
			})

			// Remove LoadBalancer target and inject delete error
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			nic.Spec.LoadBalancerTargets = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			dpdkMock.SetDeleteLoadBalancerPrefixError(fmt.Errorf("DPDK delete LB prefix failed"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete LB prefix failed"))
		})

		It("should handle ListLoadBalancerPrefixes error during reconciliation", func() {
			// Create interface with LoadBalancer target
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-list-lb-prefixes-error",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.103")},
					},
					LoadBalancerTargets: []metalnetv1alpha1.IPPrefix{
						{Prefix: netip.MustParsePrefix("10.103.0.0/24")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup NetFns mock
			netFnsMock.PreClaim(nic.UID, &ghw.PCIAddress{Domain: "0000", Bus: "01", Device: "00", Function: "0"})

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				LoadBalancerTargets: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.103.0.0/24", Underlay: "192.168.1.103"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Inject ListLoadBalancerPrefixes error
			dpdkMock.SetListLoadBalancerPrefixesError(fmt.Errorf("DPDK connection timeout"))

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error listing lb targets"))
		})
	})
})
