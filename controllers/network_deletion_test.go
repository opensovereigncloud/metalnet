// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

var _ = Describe("NetworkReconciler - Deletion", func() {
	var (
		ctx           context.Context
		ns            *corev1.Namespace
		network       *metalnetv1alpha1.Network
		reconciler    *NetworkReconciler
		dpdkMock      *mocks.DPDKClientMock
		routeUtilMock *mocks.RouteUtilMock
	)

	BeforeEach(func() {
		var err error
		ctx = context.Background()

		// Create namespace
		ns = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "testns-",
			},
		}
		err = k8sClient.Create(ctx, ns)
		Expect(err).NotTo(HaveOccurred())

		// Create fresh network for each test
		network = createTestNetwork(ns.Name)

		// Initialize mocks
		dpdkMock = mocks.NewDPDKClientMock()
		routeUtilMock = mocks.NewRouteUtilMock()

		// Create default router address
		defaultRouterAddr := createMockRouterAddr()

		// Create reconciler
		reconciler = &NetworkReconciler{
			Client:            k8sClient,
			APIReader:         k8sClient,
			Scheme:            scheme.Scheme,
			DPDK:              dpdkMock,
			RouteUtil:         routeUtilMock,
			MetalnetCache:     nil,
			DefaultRouterAddr: defaultRouterAddr,
			NodeName:          testNode,
			EnableIPv6Support: true,
			ControllerID:      "controller-a",
			ControllerHash:    "test-hash-a",
			ReadyNeeded:       1,
			Control: &control.ReconcileControl{
				SkipReconcile: false,
			},
		}
	})

	AfterEach(func() {
		cleanupNetworkTest(ctx, ns, dpdkMock, routeUtilMock)
	})

	Context("Network Deletion and Cleanup", func() {
		It("should skip deletion if no finalizer present", func() {
			// Create Network without finalizer
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Delete the network without adding finalizer
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Without finalizer, object is immediately deleted, so reconcile will find nothing
			// Reconcile should handle not-found gracefully
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Should complete without error and no requeue
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify Unsubscribe was NOT called (network was already gone)
			Expect(routeUtilMock.UnsubscribeCallCount()).To(Equal(0))
		})

		It("should unsubscribe from metalbond on deletion", func() {
			// Create Network without finalizer
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// First reconcile to add finalizer
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp and finalizer
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Assertions
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())
			Expect(routeUtilMock.UnsubscribeCallCount()).To(Equal(1))
		})

		It("should delete IPv4 default route on deletion", func() {
			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Assertions
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify DeleteRoute was called for IPv4
			// (Mock tracks this via call count or state)
			Expect(dpdkMock.DeleteRouteCallCount()).To(BeNumerically(">=", 1))
		})

		It("should delete IPv6 default route on deletion", func() {
			// Ensure IPv6 is enabled
			reconciler.EnableIPv6Support = true

			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Assertions
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// With IPv6 enabled, DeleteRoute should be called twice (IPv4 and IPv6)
			Expect(dpdkMock.DeleteRouteCallCount()).To(Equal(2))
		})

		It("should remove finalizer after cleanup", func() {
			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Assertions
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify finalizer was removed - the Network might already be garbage collected
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, network)

			// After successful deletion, Network should be gone or finalizers removed
			if err == nil {
				// Network still exists - finalizers should be empty
				Expect(network.Finalizers).To(BeEmpty())
			} else {
				// Network was garbage collected after finalizer removal - this is expected
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			}
		})

		It("should handle Unsubscribe error during deletion", func() {
			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure Unsubscribe to fail
			routeUtilMock.SetUnsubscribeError(fmt.Errorf("unsubscribe failed"))

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Should fail due to unsubscribe error
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error unsubscribing"))

			// Should not requeue
			Expect(result.Requeue).To(BeFalse())
		})

		It("should handle DeleteRoute error during deletion", func() {
			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DeleteRoute to fail
			dpdkMock.SetDeleteRouteError(fmt.Errorf("route deletion failed"))

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Should fail due to delete route error
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error deleting ipv4 route"))

			// Should not requeue
			Expect(result.Requeue).To(BeFalse())
		})

		It("should ignore NO_VNI error during route deletion", func() {
			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DeleteRoute to fail with NO_VNI (which should be ignored)
			dpdkMock.SetDeleteRouteError(dpdkerrors.NewStatusError(dpdkerrors.NO_VNI, "VNI not found"))

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Should succeed because NO_VNI is ignored
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())
		})

		It("should ignore ROUTE_NOT_FOUND error during route deletion", func() {
			// Create Network with finalizer
			network.Finalizers = []string{"networking.metalnet.ironcore.dev/network-testNode-controller-a"}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			// Configure DeleteRoute to fail with ROUTE_NOT_FOUND (which should be ignored)
			dpdkMock.SetDeleteRouteError(dpdkerrors.NewStatusError(dpdkerrors.ROUTE_NOT_FOUND, "route not found"))

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Should succeed because ROUTE_NOT_FOUND is ignored
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())
		})

		It("should handle full deletion lifecycle", func() {
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

			// Reconcile until done (creation phase)
			Expect(reconcileNetworkUntilDone(reconciler, network.Name, ns.Name, ctx)).To(Succeed())

			// Verify finalizer was added
			expectNetworkFinalizer(ctx, network)

			// Verify Unsubscribe was NOT called yet (only Subscribe)
			initialUnsubscribeCalls := routeUtilMock.UnsubscribeCallCount()
			Expect(initialUnsubscribeCalls).To(Equal(0))

			// Delete Network
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Fetch updated network to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      network.Name,
				Namespace: ns.Name,
			}, network)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
					Name:      network.Name,
				},
			})

			// Assertions
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify Unsubscribe was called during deletion
			finalUnsubscribeCalls := routeUtilMock.UnsubscribeCallCount()
			Expect(finalUnsubscribeCalls).To(Equal(1))

			// Verify routes were deleted
			Expect(dpdkMock.DeleteRouteCallCount()).To(BeNumerically(">=", 1))
		})
	})
})
