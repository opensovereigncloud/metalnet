// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
)

var _ = Describe("NetworkReconciler - High Availability", func() {
	var (
		ctx context.Context
		ns  *corev1.Namespace
	)

	BeforeEach(func() {
		// We don't use setupNetworkTest here because HA tests create their own reconcilerA/B
		ctx = context.Background()

		// Create namespace for tests
		ns = &corev1.Namespace{}
		ns.GenerateName = "testns-"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
	})

	AfterEach(func() {
		// Cleanup namespace
		Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
	})

	Context("High Availability - Dual Controller", func() {
		var (
			reconcilerA    *NetworkReconciler
			reconcilerB    *NetworkReconciler
			dpdkMockA      *mocks.DPDKClientMock
			dpdkMockB      *mocks.DPDKClientMock
			routeUtilMockA *mocks.RouteUtilMock
			routeUtilMockB *mocks.RouteUtilMock
		)

		BeforeEach(func() {
			// Create mocks for Controller A
			dpdkMockA = mocks.NewDPDKClientMock()
			routeUtilMockA = mocks.NewRouteUtilMock()

			// Create mocks for Controller B
			dpdkMockB = mocks.NewDPDKClientMock()
			routeUtilMockB = mocks.NewRouteUtilMock()

			// Create default router address for tests
			defaultRouterAddr := createMockRouterAddr()

			// Create reconciler A (primary controller)
			reconcilerA = &NetworkReconciler{
				Client:            k8sClient,
				APIReader:         k8sClient,
				Scheme:            scheme.Scheme,
				DPDK:              dpdkMockA,
				RouteUtil:         routeUtilMockA,
				MetalnetCache:     nil,
				DefaultRouterAddr: defaultRouterAddr,
				NodeName:          testNode,
				EnableIPv6Support: true,
				ControllerID:      "controller-a", // HA: Controller A identifier
				ControllerHash:    "hash-a-001",   // HA: Controller A instance hash
				ReadyNeeded:       2,              // HA: Both controllers must be ready
				Control: &control.ReconcileControl{
					SkipReconcile: false,
				},
			}

			// Create reconciler B (secondary controller)
			reconcilerB = &NetworkReconciler{
				Client:            k8sClient,
				APIReader:         k8sClient,
				Scheme:            scheme.Scheme,
				DPDK:              dpdkMockB,
				RouteUtil:         routeUtilMockB,
				MetalnetCache:     nil,
				DefaultRouterAddr: defaultRouterAddr,
				NodeName:          testNode,
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
			// Create Network
			network := createTestNetwork(ns.Name)
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DPDK mocks to return VNI in use
			dpdkMockA.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})
			dpdkMockB.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Controller A reconciles until complete
			Expect(reconcileNetworkUntilDone(reconcilerA, network.Name, network.Namespace, ctx)).To(Succeed())

			// Re-fetch to verify Controller A added its finalizer
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, network)).To(Succeed())

			// Verify Controller A's finalizer present (format: network-testNode-controller-a)
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))

			// Verify Controller A subscribed to metalbond
			Expect(routeUtilMockA.SubscribeCallCount()).To(BeNumerically(">=", 1))

			// Controller B reconciles the same Network
			Expect(reconcileNetworkUntilDone(reconcilerB, network.Name, network.Namespace, ctx)).To(Succeed())

			// Re-fetch to verify both finalizers exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, network)).To(Succeed())

			// Verify both finalizers present
			Expect(network.ObjectMeta.Finalizers).To(HaveLen(2))
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-b"))

			// Verify Controller B also subscribed to metalbond
			Expect(routeUtilMockB.SubscribeCallCount()).To(BeNumerically(">=", 1))
		})

		It("should preserve other controller's finalizer when updating", func() {
			// Create Network
			network := createTestNetwork(ns.Name)
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DPDK mocks
			dpdkMockA.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})
			dpdkMockB.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Controller A reconciles
			Expect(reconcileNetworkUntilDone(reconcilerA, network.Name, network.Namespace, ctx)).To(Succeed())

			// Verify Controller A's finalizer
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: network.Name, Namespace: network.Namespace}, network)).To(Succeed())
			Expect(network.ObjectMeta.Finalizers).To(HaveLen(1))
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))

			// Controller B reconciles
			Expect(reconcileNetworkUntilDone(reconcilerB, network.Name, network.Namespace, ctx)).To(Succeed())

			// Verify both finalizers preserved
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: network.Name, Namespace: network.Namespace}, network)).To(Succeed())
			Expect(network.ObjectMeta.Finalizers).To(HaveLen(2))

			// Verify both controllers present
			foundA := false
			foundB := false
			for _, finalizer := range network.ObjectMeta.Finalizers {
				if finalizer == "networking.metalnet.ironcore.dev/network-testNode-controller-a" {
					foundA = true
				}
				if finalizer == "networking.metalnet.ironcore.dev/network-testNode-controller-b" {
					foundB = true
				}
			}
			Expect(foundA).To(BeTrue(), "Controller A finalizer should be preserved")
			Expect(foundB).To(BeTrue(), "Controller B finalizer should be present")
		})

		It("should handle controller restart (hash change)", func() {
			// Create Network
			network := createTestNetwork(ns.Name)
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DPDK mock
			dpdkMockA.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Controller A reconciles with initial hash
			Expect(reconcileNetworkUntilDone(reconcilerA, network.Name, network.Namespace, ctx)).To(Succeed())

			// Verify initial finalizer with hash-a-001
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: network.Name, Namespace: network.Namespace}, network)).To(Succeed())
			Expect(network.ObjectMeta.Finalizers).To(HaveLen(1))
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))

			// Get initial subscription count
			initialSubscribeCount := routeUtilMockA.SubscribeCallCount()

			// Simulate Controller A restart - new hash
			reconcilerA.ControllerHash = "hash-a-002"

			// Reconcile with new hash (should detect mismatch and re-reconcile)
			Expect(reconcileNetworkUntilDone(reconcilerA, network.Name, network.Namespace, ctx)).To(Succeed())

			// Verify finalizer still exists (same ControllerID, different hash)
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: network.Name, Namespace: network.Namespace}, network)).To(Succeed())
			Expect(network.ObjectMeta.Finalizers).To(HaveLen(1))
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))

			// Verify controller re-reconciled (subscription should have been called again)
			Expect(routeUtilMockA.SubscribeCallCount()).To(BeNumerically(">", initialSubscribeCount))
		})

		It("should skip reconciliation when already processed by controller", func() {
			// Create Network
			network := createTestNetwork(ns.Name)
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DPDK mock
			dpdkMockA.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// First reconcile - should process fully
			Expect(reconcileNetworkUntilDone(reconcilerA, network.Name, network.Namespace, ctx)).To(Succeed())

			// Verify initial reconciliation happened
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: network.Name, Namespace: network.Namespace}, network)).To(Succeed())
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))

			// Get counts after first reconciliation
			firstSubscribeCount := routeUtilMockA.SubscribeCallCount()
			firstGetVniCount := dpdkMockA.GetVniCallCount()

			// Second reconcile - same generation, same hash, should be idempotent
			// Network doesn't have ObservedGeneration tracking like NetworkInterface,
			// but it should still be idempotent (finalizer already exists, routes already exist)
			Expect(reconcileNetworkUntilDone(reconcilerA, network.Name, network.Namespace, ctx)).To(Succeed())

			// Verify second reconciliation was idempotent
			// Subscribe should be called again (it's idempotent in metalbond)
			Expect(routeUtilMockA.SubscribeCallCount()).To(BeNumerically(">=", firstSubscribeCount))

			// GetVni should be called again (checking if VNI exists)
			Expect(dpdkMockA.GetVniCallCount()).To(BeNumerically(">", firstGetVniCount))

			// Finalizers should remain the same
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: network.Name, Namespace: network.Namespace}, network)).To(Succeed())
			Expect(network.ObjectMeta.Finalizers).To(HaveLen(1))
			Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))
		})
	})
})
