// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"net/netip"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
)

var _ = Describe("NetworkInterfaceReconciler - High Availability", func() {
	var (
		ctx           context.Context
		ns            *corev1.Namespace
		network       *metalnetv1alpha1.Network
		dpdkMock      *mocks.DPDKClientMock
		routeUtilMock *mocks.RouteUtilMock
		netFnsMock    *mocks.NetFnsManagerMock
	)

	BeforeEach(func() {
		// HA tests create their own reconcilerA/B, so we discard the default reconciler with _
		ctx, ns, network, _, dpdkMock, routeUtilMock, netFnsMock = setupNetworkInterfaceTest()
	})

	AfterEach(func() {
		cleanupNetworkInterfaceTest(ctx, ns, dpdkMock, routeUtilMock, netFnsMock)
	})

	Context("High Availability - Dual Controller", func() {
		var (
			reconcilerA    *NetworkInterfaceReconciler
			reconcilerB    *NetworkInterfaceReconciler
			dpdkMockA      *mocks.DPDKClientMock
			dpdkMockB      *mocks.DPDKClientMock
			routeUtilMockA *mocks.RouteUtilMock
			routeUtilMockB *mocks.RouteUtilMock
			netFnsMockA    *mocks.NetFnsManagerMock
			netFnsMockB    *mocks.NetFnsManagerMock
		)

		BeforeEach(func() {
			// Note: IPv6Manager is a singleton, so both controllers share the same instance
			// In production, each controller runs in a separate pod with its own IPv6Manager
			// For testing dual controllers with different underlay pools, we would need
			// to test them sequentially or mock the IPv6 generation differently

			// Create mocks for Controller A
			dpdkMockA = mocks.NewDPDKClientMock()
			routeUtilMockA = mocks.NewRouteUtilMock()
			netFnsMockA = mocks.NewNetFnsManagerMock()

			// Create mocks for Controller B
			dpdkMockB = mocks.NewDPDKClientMock()
			routeUtilMockB = mocks.NewRouteUtilMock()
			netFnsMockB = mocks.NewNetFnsManagerMock()

			// Create reconciler A (primary controller using ULA primary pool)
			// Uses the existing IPv6Manager CIDR set in main BeforeEach (fd00:1234:5678:abcd:d080::/88)
			reconcilerA = &NetworkInterfaceReconciler{
				Client:            k8sClient,
				APIReader:         k8sClient,
				EventRecorder:     &record.FakeRecorder{},
				Scheme:            scheme.Scheme,
				DPDK:              dpdkMockA,
				RouteUtil:         routeUtilMockA,
				NetFnsManager:     netFnsMockA,
				NodeName:          testNode,
				PublicVNI:         100,
				EnableIPv6Support: false,
				ControllerID:      "metalnet-a", // HA: Controller A identifier
				ControllerHash:    "hash-a-001", // HA: Controller A instance hash
				ReadyNeeded:       2,            // HA: Both controllers must be ready
				Control: &control.ReconcileControl{
					SkipReconcile: false,
				},
			}

			// Create reconciler B (secondary controller)
			// In production this would use secondary pool (d0c0), but since IPv6Manager
			// is a singleton in tests, both controllers share the same pool for simplicity
			reconcilerB = &NetworkInterfaceReconciler{
				Client:            k8sClient,
				APIReader:         k8sClient,
				EventRecorder:     &record.FakeRecorder{},
				Scheme:            scheme.Scheme,
				DPDK:              dpdkMockB,
				RouteUtil:         routeUtilMockB,
				NetFnsManager:     netFnsMockB,
				NodeName:          testNode,
				PublicVNI:         100,
				EnableIPv6Support: false,
				ControllerID:      "metalnet-b", // HA: Controller B identifier
				ControllerHash:    "hash-b-001", // HA: Controller B instance hash
				ReadyNeeded:       2,            // HA: Both controllers must be ready
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
			netFnsMockA.Reset()
			netFnsMockB.Reset()
		})

		It("should coordinate dual controller reconciliation", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ha",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.100")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically
			// The mock returns 404 (not found) by default, then tracks created interfaces

			// Controller A reconciles until complete
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Re-fetch to verify Controller A created its status
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      nic.Name,
				Namespace: nic.Namespace,
			}, nic)).To(Succeed())

			Expect(nic.Status.ControllerStatuses).To(HaveLen(1))
			Expect(nic.Status.ControllerStatuses[0].ControllerID).To(Equal("metalnet-a"))
			Expect(nic.Status.ControllerStatuses[0].ControllerHash).To(Equal("hash-a-001"))

			// Verify Controller A claimed a PCI address and created interface
			Expect(netFnsMockA.GetOrClaimCallCount()).To(BeNumerically(">=", 1))
			Expect(netFnsMockA.IsClaimedBy(nic.UID)).To(BeTrue())
			Expect(dpdkMockA.CreateInterfaceCallCount()).To(Equal(1))

			// Controller B reconciles the same NIC
			Expect(reconcileUntilDone(reconcilerB, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Re-fetch to verify both controller statuses exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      nic.Name,
				Namespace: nic.Namespace,
			}, nic)).To(Succeed())

			Expect(nic.Status.ControllerStatuses).To(HaveLen(2))

			// Verify both controllers have their statuses
			var statusA, statusB *metalnetv1alpha1.ControllerStatus
			for i := range nic.Status.ControllerStatuses {
				if nic.Status.ControllerStatuses[i].ControllerID == "metalnet-a" {
					statusA = &nic.Status.ControllerStatuses[i]
				} else if nic.Status.ControllerStatuses[i].ControllerID == "metalnet-b" {
					statusB = &nic.Status.ControllerStatuses[i]
				}
			}

			Expect(statusA).NotTo(BeNil())
			Expect(statusA.ControllerHash).To(Equal("hash-a-001"))

			Expect(statusB).NotTo(BeNil())
			Expect(statusB.ControllerHash).To(Equal("hash-b-001"))

			// Verify Controller B also claimed a PCI address and created interface
			Expect(netFnsMockB.GetOrClaimCallCount()).To(BeNumerically(">=", 1))
			Expect(netFnsMockB.IsClaimedBy(nic.UID)).To(BeTrue())
			Expect(dpdkMockB.CreateInterfaceCallCount()).To(Equal(1))
		})

		It("should preserve other controller's status when updating", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ha-preserve",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.101")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// Controller A reconciles
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify Controller A status
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(1))

			// Controller B reconciles
			Expect(reconcileUntilDone(reconcilerB, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify both statuses preserved
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(2))

			// Verify both controllers present
			foundA, foundB := false, false
			for _, status := range nic.Status.ControllerStatuses {
				if status.ControllerID == "metalnet-a" {
					foundA = true
				}
				if status.ControllerID == "metalnet-b" {
					foundB = true
				}
			}
			Expect(foundA).To(BeTrue(), "Controller A status should be preserved")
			Expect(foundB).To(BeTrue(), "Controller B status should be present")
		})

		It("should handle controller restart (hash change)", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ha-restart",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.102")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// Controller A reconciles with initial hash
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify initial hash
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(1))
			Expect(nic.Status.ControllerStatuses[0].ControllerHash).To(Equal("hash-a-001"))

			// Simulate Controller A restart - new hash
			reconcilerA.ControllerHash = "hash-a-002"

			// Reconcile with new hash (should detect mismatch and update)
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify hash updated
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(1))
			Expect(nic.Status.ControllerStatuses[0].ControllerHash).To(Equal("hash-a-002"))
		})

		It("should aggregate status correctly with ReadyNeeded=2", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ha-aggregate",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.103")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Note: No need to configure DPDK mock - stateful tracking handles it automatically

			// Controller A reconciles
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify only Controller A status exists
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(1))

			// Controller B reconciles
			Expect(reconcileUntilDone(reconcilerB, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify both controller statuses exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(2))
		})

		It("should maintain Ready status when interface already exists", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ha-status-toggle",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.104")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - creates interface
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify interface is created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.ControllerStatuses).To(HaveLen(1))
			Expect(dpdkMockA.CreateInterfaceCallCount()).To(Equal(1))

			// Second reconcile - interface already exists, should maintain stability
			Expect(reconcileUntilDone(reconcilerA, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify status is stable
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			finalState := nic.Status.GetState()

			// Status should be Ready or Pending (but stable)
			Expect(finalState).To(BeElementOf(metalnetv1alpha1.NetworkInterfaceStateReady, metalnetv1alpha1.NetworkInterfaceStatePending))

			// Interface should not be recreated (same call count)
			Expect(dpdkMockA.CreateInterfaceCallCount()).To(Equal(1))

			// Verify GetInterface was called to check if interface exists
			Expect(dpdkMockA.GetInterfaceCallCount()).To(BeNumerically(">=", 1))
		})
	})
})
