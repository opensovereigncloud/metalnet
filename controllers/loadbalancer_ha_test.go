// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"net/netip"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	"github.com/ironcore-dev/metalnet/internal"
	"github.com/ironcore-dev/metalnet/ipv6manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
)

var _ = Describe("LoadBalancerReconciler - High Availability", func() {
	var (
		ctx           context.Context
		ns            *corev1.Namespace
		network       *metalnetv1alpha1.Network
		dpdkMock      *mocks.DPDKClientMock
		routeUtilMock *mocks.RouteUtilMock
	)

	BeforeEach(func() {
		// HA tests create their own reconcilerA/B, so we discard the default reconciler with _
		ctx, ns, network, _, _, dpdkMock, routeUtilMock = setupLoadBalancerTest()
	})

	AfterEach(func() {
		cleanupLoadBalancerTest(ctx, ns, dpdkMock, routeUtilMock)
	})

	Context("High Availability - Dual Controller", func() {
		var (
			reconcilerA    *LoadBalancerReconciler
			reconcilerB    *LoadBalancerReconciler
			dpdkMockA      *mocks.DPDKClientMock
			dpdkMockB      *mocks.DPDKClientMock
			routeUtilMockA *mocks.RouteUtilMock
			routeUtilMockB *mocks.RouteUtilMock
		)

		BeforeEach(func() {
			// Note: IPv6Manager is a singleton, so both controllers share the same instance
			// In production, each controller runs in a separate pod with its own IPv6Manager
			// For testing dual controllers with different underlay pools, we would need
			// to test them sequentially or mock the IPv6 generation differently

			// Create mocks for Controller A
			dpdkMockA = mocks.NewDPDKClientMock()
			routeUtilMockA = mocks.NewRouteUtilMock()

			// Create mocks for Controller B
			dpdkMockB = mocks.NewDPDKClientMock()
			routeUtilMockB = mocks.NewRouteUtilMock()

			// Create reconciler A (primary controller using ULA primary pool)
			// Uses the existing IPv6Manager CIDR set in main BeforeEach (fd00:1234:5678:abcd:d080::/88)
			reconcilerA = &LoadBalancerReconciler{
				Client:            k8sClient,
				APIReader:         k8sClient,
				EventRecorder:     &record.FakeRecorder{},
				Scheme:            scheme.Scheme,
				DPDK:              dpdkMockA,
				RouteUtil:         routeUtilMockA,
				MetalnetCache:     internal.NewMetalnetCache(nil),
				NodeName:          testNode,
				PublicVNI:         100,
				EnableIPv6Support: true,
				ControllerID:      "controller-a", // HA: Controller A identifier
				ControllerHash:    "hash-a-001",   // HA: Controller A instance hash
				ReadyNeeded:       2,              // HA: Both controllers must be ready
				Control: &control.ReconcileControl{
					SkipReconcile: false,
				},
			}

			// Create reconciler B (secondary controller)
			// In production this would use secondary pool (d0c0), but since IPv6Manager
			// is a singleton in tests, both controllers share the same pool for simplicity
			reconcilerB = &LoadBalancerReconciler{
				Client:            k8sClient,
				APIReader:         k8sClient,
				EventRecorder:     &record.FakeRecorder{},
				Scheme:            scheme.Scheme,
				DPDK:              dpdkMockB,
				RouteUtil:         routeUtilMockB,
				MetalnetCache:     internal.NewMetalnetCache(nil),
				NodeName:          testNode,
				PublicVNI:         100,
				EnableIPv6Support: true,
				ControllerID:      "controller-b", // HA: Controller B identifier
				ControllerHash:    "hash-b-001",   // HA: Controller B instance hash
				ReadyNeeded:       2,              // HA: Both controllers must be ready
				Control: &control.ReconcileControl{
					SkipReconcile: false,
				},
			}
		})

		AfterEach(func() {
			// Reset mocks
			dpdkMockA.Reset()
			dpdkMockB.Reset()
			routeUtilMockA.Reset()
			routeUtilMockB.Reset()
		})

		It("should coordinate dual controller reconciliation", func() {
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-ha",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("11.5.5.100"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{Protocol: string(corev1.ProtocolTCP), Port: 80},
					},
					NodeName: &testNode,
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically
			// The mock returns 404 (not found) by default, then tracks created LoadBalancers

			// Controller A reconciles until complete
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Re-fetch to verify Controller A created its status
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			Expect(lb.Status.ControllerStatuses).To(HaveLen(1))
			Expect(lb.Status.ControllerStatuses[0].ControllerID).To(Equal("controller-a"))
			Expect(lb.Status.ControllerStatuses[0].ControllerHash).To(Equal("hash-a-001"))

			// Verify Controller A created LoadBalancer and announced routes
			Expect(dpdkMockA.CreateLoadBalancerCallCount()).To(Equal(1))
			Expect(routeUtilMockA.AnnounceRouteCallCount()).To(BeNumerically(">=", 1))

			// Verify Controller A's finalizer
			Expect(lb.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/loadBalancer-controller-a"))

			// Controller B reconciles the same LoadBalancer
			Expect(reconcileLoadBalancerUntilDone(reconcilerB, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Re-fetch to verify both controller statuses exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			Expect(lb.Status.ControllerStatuses).To(HaveLen(2))

			// Verify both controllers have their statuses
			var statusA, statusB *metalnetv1alpha1.ControllerStatus
			for i := range lb.Status.ControllerStatuses {
				if lb.Status.ControllerStatuses[i].ControllerID == "controller-a" {
					statusA = &lb.Status.ControllerStatuses[i]
				} else if lb.Status.ControllerStatuses[i].ControllerID == "controller-b" {
					statusB = &lb.Status.ControllerStatuses[i]
				}
			}

			Expect(statusA).NotTo(BeNil())
			Expect(statusA.ControllerHash).To(Equal("hash-a-001"))

			Expect(statusB).NotTo(BeNil())
			Expect(statusB.ControllerHash).To(Equal("hash-b-001"))

			// Verify Controller B also created LoadBalancer and announced routes
			Expect(dpdkMockB.CreateLoadBalancerCallCount()).To(Equal(1))
			Expect(routeUtilMockB.AnnounceRouteCallCount()).To(BeNumerically(">=", 1))

			// Verify Controller B's finalizer
			Expect(lb.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/loadBalancer-controller-b"))

			// Verify both finalizers present
			Expect(lb.ObjectMeta.Finalizers).To(HaveLen(2))
		})

		It("should preserve other controller's status when updating", func() {
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-ha-preserve",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("11.5.5.101"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{Protocol: string(corev1.ProtocolTCP), Port: 80},
					},
					NodeName: &testNode,
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// Controller A reconciles
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify Controller A status
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(1))

			// Controller B reconciles
			Expect(reconcileLoadBalancerUntilDone(reconcilerB, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify both statuses preserved
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(2))

			// Verify both controllers present
			foundA, foundB := false, false
			for _, status := range lb.Status.ControllerStatuses {
				if status.ControllerID == "controller-a" {
					foundA = true
				}
				if status.ControllerID == "controller-b" {
					foundB = true
				}
			}
			Expect(foundA).To(BeTrue(), "Controller A status should be preserved")
			Expect(foundB).To(BeTrue(), "Controller B status should be present")
		})

		It("should handle controller restart (hash change)", func() {
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-ha-restart",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("11.5.5.102"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{Protocol: string(corev1.ProtocolTCP), Port: 80},
					},
					NodeName: &testNode,
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// Controller A reconciles with initial hash
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify initial hash
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(1))
			Expect(lb.Status.ControllerStatuses[0].ControllerHash).To(Equal("hash-a-001"))

			// Simulate Controller A restart - new hash
			reconcilerA.ControllerHash = "hash-a-002"

			// Reconcile with new hash (should detect mismatch and update)
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify hash updated
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(1))
			Expect(lb.Status.ControllerStatuses[0].ControllerHash).To(Equal("hash-a-002"))
		})

		It("should skip reconciliation when already processed", func() {
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-ha-skip",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("11.5.5.103"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{Protocol: string(corev1.ProtocolTCP), Port: 80},
					},
					NodeName: &testNode,
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// First reconcile - creates LoadBalancer
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify LoadBalancer created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(1))
			Expect(dpdkMockA.CreateLoadBalancerCallCount()).To(Equal(1))

			// Second reconcile - LoadBalancer already exists, should skip
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify LoadBalancer was not recreated (same call count)
			Expect(dpdkMockA.CreateLoadBalancerCallCount()).To(Equal(1))

			// Verify GetLoadBalancer was called to check if LoadBalancer exists
			Expect(dpdkMockA.GetLoadBalancerCallCount()).To(BeNumerically(">=", 1))
		})

		It("should coordinate IPv6 reservation between controllers", func() {
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-ha-ipv6",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("11.5.5.104"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{Protocol: string(corev1.ProtocolTCP), Port: 80},
					},
					NodeName: &testNode,
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Note: IPv6Manager is a singleton shared between both controllers
			ipv6mgr := ipv6manager.GetInstance()

			// Controller A reconciles (creates reservation)
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify Controller A created reservation
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.Reservation).NotTo(BeNil())
			Expect(lb.Status.Reservation.IP).NotTo(BeNil())
			reservationA := lb.Status.Reservation.IP.Underlay

			// Verify IPv6 reservation created
			Expect(reservationA).NotTo(BeEmpty())
			underlayA, err := netip.ParseAddr(reservationA)
			Expect(err).NotTo(HaveOccurred())

			// Controller B reconciles (should reuse existing reservation)
			Expect(reconcileLoadBalancerUntilDone(reconcilerB, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify Controller B reused the same reservation
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.Reservation).NotTo(BeNil())
			Expect(lb.Status.Reservation.IP).NotTo(BeNil())
			reservationB := lb.Status.Reservation.IP.Underlay

			// Verify reservation unchanged
			Expect(reservationB).To(Equal(reservationA), "Controller B should reuse Controller A's reservation")

			// Verify no duplicate IPv6 allocation
			underlayB, err := netip.ParseAddr(reservationB)
			Expect(err).NotTo(HaveOccurred())
			Expect(underlayB).To(Equal(underlayA))

			// Verify IPv6Manager has the reservation
			existingIPs := ipv6mgr.GetExistingIPs()
			Expect(existingIPs).To(ContainElement(reservationA), "IPv6Manager should have the reservation")

			// Verify both controllers created their own DPDK LoadBalancers
			Expect(dpdkMockA.CreateLoadBalancerCallCount()).To(Equal(1))
			Expect(dpdkMockB.CreateLoadBalancerCallCount()).To(Equal(1))
		})

		It("should aggregate status correctly with ReadyNeeded=2", func() {
			lb := &metalnetv1alpha1.LoadBalancer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb-ha-aggregate",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.LoadBalancerSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
					IPFamily:   corev1.IPv4Protocol,
					IP: metalnetv1alpha1.IP{
						Addr: netip.MustParseAddr("11.5.5.105"),
					},
					Ports: []metalnetv1alpha1.LBPort{
						{Protocol: string(corev1.ProtocolTCP), Port: 80},
					},
					NodeName: &testNode,
				},
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// Controller A reconciles
			Expect(reconcileLoadBalancerUntilDone(reconcilerA, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify only Controller A status exists
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(1))

			// Controller B reconciles
			Expect(reconcileLoadBalancerUntilDone(reconcilerB, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify both controller statuses exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: lb.Name, Namespace: lb.Namespace}, lb)).To(Succeed())
			Expect(lb.Status.ControllerStatuses).To(HaveLen(2))
		})
	})
})
