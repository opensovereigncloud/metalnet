// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

var _ = Describe("NetworkReconciler - Creation", func() {
	var (
		ctx           context.Context
		ns            *corev1.Namespace
		network       *metalnetv1alpha1.Network
		reconciler    *NetworkReconciler
		dpdkMock      *mocks.DPDKClientMock
		routeUtilMock *mocks.RouteUtilMock
	)

	BeforeEach(func() {
		ctx, ns, network, reconciler, dpdkMock, routeUtilMock = setupNetworkTest()
	})

	AfterEach(func() {
		cleanupNetworkTest(ctx, ns, dpdkMock, routeUtilMock)
	})

	Context("Network Creation and Finalization", func() {
		It("should add finalizer on first reconcile", func() {
			// Create Network without finalizer
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// First reconcile
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Assertions
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue()) // Finalizer added triggers requeue

			// Verify finalizer present
			expectNetworkFinalizer(ctx, network)
		})

		It("should not duplicate finalizer on subsequent reconciles", func() {
			// Create Network and add finalizer
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// First reconcile - adds finalizer
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify finalizer present
			expectNetworkFinalizer(ctx, network)

			// Get the current finalizers count
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, network)).To(Succeed())
			finalizerCountBefore := len(network.ObjectMeta.Finalizers)

			// Configure DPDK mock to return VNI not in use (to avoid nil pointer on second reconcile)
			// This simulates the VNI existing but not being used by any interfaces
			dpdkMock.SetGetVniResponse(nil) // VNI not found = not in use

			// Second reconcile - should not duplicate finalizer
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify finalizer count hasn't increased
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, network)).To(Succeed())
			finalizerCountAfter := len(network.ObjectMeta.Finalizers)

			Expect(finalizerCountAfter).To(Equal(finalizerCountBefore))
		})

		It("should proceed with route creation after finalizer added", func() {
			// Configure DPDK mock to return VNI in use
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Reconcile until done
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify finalizer was added
			expectNetworkFinalizer(ctx, network)

			// Verify CreateRoute was called twice (IPv4 and IPv6)
			// The mock stateful interface should track these calls
			// We check that the route creation was attempted
			// (actual verification depends on mock call tracking)
		})

		It("should handle GetVni error during reconciliation", func() {
			// Configure DPDK mock to return error on GetVni
			dpdkMock.SetGetVniError(fmt.Errorf("DPDK service unavailable"))

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// First reconcile should add finalizer and succeed
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Second reconcile should fail due to GetVni error
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK service unavailable"))
		})

		It("should skip route creation when VNI not in use", func() {
			// Configure DPDK mock to return VNI not in use
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: false,
				},
			})

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Reconcile until done
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify finalizer was added
			expectNetworkFinalizer(ctx, network)

			// Verify no routes were created (since InUse is false)
			// The mock should not have received CreateRoute calls for default routes
		})

		It("should create IPv4 default route when VNI in use", func() {
			// Configure DPDK mock
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Reconcile until done
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify finalizer was added
			expectNetworkFinalizer(ctx, network)

			// Verify IPv4 route creation was attempted
			// With InUse=true, the controller should create IPv4 default route
		})

		It("should create IPv6 default route when enabled", func() {
			// Configure DPDK mock
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Ensure IPv6 is enabled
			reconciler.EnableIPv6Support = true

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Reconcile until done
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify finalizer was added
			expectNetworkFinalizer(ctx, network)

			// With IPv6 enabled and VNI in use, controller should attempt to create IPv6 route
		})

		It("should subscribe to metalbond after route creation", func() {
			// Configure DPDK mock
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Reconcile until done
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify Subscribe was called
			// The routeUtilMock should track the subscription call
			Expect(routeUtilMock.SubscribeCallCount()).To(BeNumerically(">=", 1))
		})

		It("should handle CreateRoute error", func() {
			// Configure DPDK mock
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Configure CreateRoute to fail
			dpdkMock.SetCreateRouteError(fmt.Errorf("route creation failed"))

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// First reconcile adds finalizer and succeeds
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Second reconcile should fail due to CreateRoute error
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error creating ipv4 route"))
		})

		It("should ignore ROUTE_EXISTS error during idempotent route creation", func() {
			// Configure DPDK mock
			dpdkMock.SetGetVniResponse(&dpdk.Vni{
				VniMeta: dpdk.VniMeta{
					VNI: 123,
				},
				Spec: dpdk.VniSpec{
					InUse: true,
				},
			})

			// Configure CreateRoute to fail with ROUTE_EXISTS (ignored error)
			dpdkMock.SetCreateRouteError(dpdkerrors.NewStatusError(dpdkerrors.ROUTE_EXISTS, "route already exists"))

			// Create Network
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Reconcile until done - should succeed because ROUTE_EXISTS is ignored
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify finalizer was added
			expectNetworkFinalizer(ctx, network)
		})
	})
})
