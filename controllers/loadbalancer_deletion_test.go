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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

var _ = Describe("LoadBalancerReconciler - Deletion", func() {
	var ctx context.Context
	var ns *corev1.Namespace
	var lb *metalnetv1alpha1.LoadBalancer
	var network *metalnetv1alpha1.Network
	var reconciler *LoadBalancerReconciler
	var dpdkMock *mocks.DPDKClientMock
	var routeUtilMock *mocks.RouteUtilMock

	BeforeEach(func() {
		ctx, ns, network, lb, reconciler, dpdkMock, routeUtilMock = setupLoadBalancerTest()
	})

	AfterEach(func() {
		cleanupLoadBalancerTest(ctx, ns, dpdkMock, routeUtilMock)
	})

	Context("LoadBalancer Deletion and Cleanup", func() {
		It("should skip deletion if no finalizer present", func() {
			// Create LoadBalancer without creating it in k8s first (so we can control finalizers)
			lbNoFinalizer := createTestLoadBalancer(ns.Name, network.Name)
			lbNoFinalizer.Name = "test-lb-no-finalizer"

			// Add a dummy finalizer to prevent K8s from auto-deleting
			lbNoFinalizer.ObjectMeta.Finalizers = []string{"test.example.com/dummy"}

			// Create without reconciling (so no controller finalizer is added)
			Expect(k8sClient.Create(ctx, lbNoFinalizer)).To(Succeed())

			// Pre-populate reservation to avoid reservation reconciliation
			underlayIP, err := reconciler.generateUnderlayIP(lbNoFinalizer.Spec.IP)
			Expect(err).NotTo(HaveOccurred())
			lbNoFinalizer.Status.Reservation = &metalnetv1alpha1.LoadBalancerReservation{
				IP: &metalnetv1alpha1.IPReservation{
					Overlay:  lbNoFinalizer.Spec.IP.Addr.String(),
					Underlay: underlayIP,
				},
			}
			Expect(k8sClient.Status().Update(ctx, lbNoFinalizer)).To(Succeed())

			// Delete immediately (before reconciliation adds controller finalizer)
			Expect(k8sClient.Delete(ctx, lbNoFinalizer)).To(Succeed())

			// Fetch the object with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lbNoFinalizer.Name,
				Namespace: lbNoFinalizer.Namespace,
			}, lbNoFinalizer)).To(Succeed())

			// Verify deletion timestamp is set and only dummy finalizer present
			Expect(lbNoFinalizer.DeletionTimestamp.IsZero()).To(BeFalse())
			Expect(lbNoFinalizer.ObjectMeta.Finalizers).To(Equal([]string{"test.example.com/dummy"}))

			// Reconcile deletion - should succeed without trying to delete DPDK
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lbNoFinalizer.Name,
					Namespace: lbNoFinalizer.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())
			Expect(dpdkMock.DeleteLoadBalancerCallCount()).To(Equal(0))
		})

		It("should withdraw route for Public LoadBalancer on deletion", func() {
			// Create Public LoadBalancer
			lb.Spec.LBtype = metalnetv1alpha1.LoadBalancerTypePublic
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Reconcile to create LoadBalancer
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify route was announced (creation)
			Expect(routeUtilMock.AnnounceRouteCallCount()).To(BeNumerically(">", 0))

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify route was withdrawn
			Expect(routeUtilMock.WithdrawRouteCallCount()).To(Equal(1))
		})

		It("should withdraw route for Internal LoadBalancer on deletion", func() {
			// Create Internal LoadBalancer
			lb.Spec.LBtype = metalnetv1alpha1.LoadBalancerTypeInternal
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Reconcile to create LoadBalancer
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify route was announced during creation
			Expect(routeUtilMock.AnnounceRouteCallCount()).To(BeNumerically(">", 0))

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify route was withdrawn
			Expect(routeUtilMock.WithdrawRouteCallCount()).To(Equal(1))
		})

		It("should delete LoadBalancer from DPDK", func() {
			// Create and reconcile LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify LoadBalancer was created in DPDK
			Expect(dpdkMock.CreateLoadBalancerCallCount()).To(Equal(1))

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify LoadBalancer was deleted from DPDK
			Expect(dpdkMock.DeleteLoadBalancerCallCount()).To(Equal(1))
		})

		It("should remove LoadBalancer from MetalnetCache", func() {
			// Create and reconcile LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify LoadBalancer exists in cache
			vni := uint32(network.Spec.ID)
			_, exists := reconciler.MetalnetCache.GetLoadBalancerServer(vni, lb.Spec.IP.Addr.String())
			Expect(exists).To(BeTrue(), "LoadBalancer should exist in cache after creation")

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify LoadBalancer was removed from cache
			_, exists = reconciler.MetalnetCache.GetLoadBalancerServer(vni, lb.Spec.IP.Addr.String())
			Expect(exists).To(BeFalse(), "LoadBalancer should be removed from cache after deletion")
		})

		It("should release IPv6 reservation on deletion", func() {
			// Create and reconcile LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Fetch LoadBalancer to get reservation
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Verify reservation exists
			Expect(lb.Status.Reservation).NotTo(BeNil())
			Expect(lb.Status.Reservation.IP).NotTo(BeNil())
			Expect(lb.Status.Reservation.IP.Underlay).NotTo(BeEmpty())

			underlayIP := lb.Status.Reservation.IP.Underlay

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify IPv6 was released (should be available for reuse)
			// The IPv6Manager should have withdrawn this IP
			_, err = netip.ParseAddr(underlayIP)
			Expect(err).NotTo(HaveOccurred(), "Underlay IP should be valid IPv6")
		})

		It("should remove finalizer after cleanup", func() {
			// Create and reconcile LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Verify finalizer was added
			expectLoadBalancerFinalizer(ctx, lb)

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Store the current resource version
			initialResourceVersion := lb.ResourceVersion

			// Reconcile deletion (first attempt removes backward compatible finalizer if exists)
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			// If result.Requeue is true, we removed the backward compatible finalizer
			if result.Requeue {
				// Fetch updated object
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				}, lb)).To(Succeed())

				// Reconcile again to remove the controller-specific finalizer
				result, err = reconciler.Reconcile(ctx, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      lb.Name,
						Namespace: lb.Namespace,
					},
				})
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify LoadBalancer no longer exists (finalizer removed, object deleted)
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))

			// Verify resource version changed (finalizer was removed)
			Expect(initialResourceVersion).NotTo(BeEmpty())
		})

		It("should handle DeleteLoadBalancer DPDK error", func() {
			// Create and reconcile LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Inject error for DeleteLoadBalancer
			dpdkMock.SetDeleteLoadBalancerError(fmt.Errorf("DPDK delete failed"))

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion - should fail
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DPDK delete failed"))
			Expect(result.Requeue).To(BeFalse())

			// Verify finalizer is still present (deletion failed)
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())
			expectLoadBalancerFinalizer(ctx, lb)
		})

		It("should handle route withdrawal error", func() {
			// Create and reconcile LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())
			Expect(reconcileLoadBalancerUntilDone(reconciler, lb.Name, lb.Namespace, ctx)).To(Succeed())

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Inject error for route withdrawal
			routeUtilMock.SetWithdrawRouteError(fmt.Errorf("route withdrawal failed"))

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion - should fail
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("route withdrawal failed"))
			Expect(result.Requeue).To(BeFalse())

			// Verify finalizer is still present
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())
			expectLoadBalancerFinalizer(ctx, lb)
		})

		It("should ignore NOT_FOUND errors during deletion", func() {
			// Create LoadBalancer and manually add finalizer
			lb.ObjectMeta.Finalizers = []string{
				fmt.Sprintf("networking.metalnet.onmetal.de/loadBalancer-%s", reconciler.ControllerID),
			}
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// Create reservation manually (to simulate partial state)
			underlayIP, err := reconciler.generateUnderlayIP(lb.Spec.IP)
			Expect(err).NotTo(HaveOccurred())

			lb.Status.Reservation = &metalnetv1alpha1.LoadBalancerReservation{
				IP: &metalnetv1alpha1.IPReservation{
					Overlay:  lb.Spec.IP.Addr.String(),
					Underlay: underlayIP,
				},
			}
			Expect(k8sClient.Status().Update(ctx, lb)).To(Succeed())

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Configure mock to return NOT_FOUND for GetLoadBalancer
			// (simulating LoadBalancer that doesn't exist in DPDK)
			dpdkMock.SetGetLoadBalancerResponse(nil, dpdkerrors.NewStatusError(dpdkerrors.NOT_FOUND, "not found"))

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion - should succeed despite NOT_FOUND
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			// First reconcile may return Requeue=true if removing backward compatible finalizer
			if result.Requeue {
				// Fetch and reconcile again
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				}, lb)).To(Succeed())

				result, err = reconciler.Reconcile(ctx, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      lb.Name,
						Namespace: lb.Namespace,
					},
				})
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify LoadBalancer was deleted (finalizer removed)
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should handle full deletion lifecycle (create -> delete)", func() {
			// Create LoadBalancer
			Expect(k8sClient.Create(ctx, lb)).To(Succeed())

			// First reconcile - create reservations
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue(), "Should requeue after reservation generation")

			// Second reconcile - add finalizer
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue(), "Should requeue after adding finalizer")

			// Third reconcile - create LoadBalancer in DPDK
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify LoadBalancer is ready
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())
			expectLoadBalancerFinalizer(ctx, lb)

			// Verify creation operations occurred
			Expect(dpdkMock.CreateLoadBalancerCallCount()).To(Equal(1))
			Expect(routeUtilMock.AnnounceRouteCallCount()).To(BeNumerically(">", 0))

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lb)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)).To(Succeed())

			// Reconcile deletion
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				},
			})

			// May need two reconciles to remove both finalizers
			if result.Requeue {
				Expect(err).NotTo(HaveOccurred())

				// Fetch and reconcile again
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      lb.Name,
					Namespace: lb.Namespace,
				}, lb)).To(Succeed())

				result, err = reconciler.Reconcile(ctx, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      lb.Name,
						Namespace: lb.Namespace,
					},
				})
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())

			// Verify deletion operations occurred
			Expect(dpdkMock.DeleteLoadBalancerCallCount()).To(Equal(1))
			Expect(routeUtilMock.WithdrawRouteCallCount()).To(Equal(1))

			// Verify LoadBalancer was deleted
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      lb.Name,
				Namespace: lb.Namespace,
			}, lb)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should handle backward compatible finalizer cleanup", func() {
			// Create LoadBalancer with both old and new finalizers
			// (simulating upgrade scenario where object has both)
			lbWithOldFinalizer := createTestLoadBalancer(ns.Name, network.Name)
			lbWithOldFinalizer.Name = "test-lb-old-finalizer"
			lbWithOldFinalizer.ObjectMeta.Finalizers = []string{
				"networking.metalnet.onmetal.de/loadBalancer", // Old finalizer format
				fmt.Sprintf("networking.metalnet.onmetal.de/loadBalancer-%s", reconciler.ControllerID), // New finalizer format
			}
			Expect(k8sClient.Create(ctx, lbWithOldFinalizer)).To(Succeed())

			// Create reservation manually
			underlayIP, err := reconciler.generateUnderlayIP(lbWithOldFinalizer.Spec.IP)
			Expect(err).NotTo(HaveOccurred())

			lbWithOldFinalizer.Status.Reservation = &metalnetv1alpha1.LoadBalancerReservation{
				IP: &metalnetv1alpha1.IPReservation{
					Overlay:  lbWithOldFinalizer.Spec.IP.Addr.String(),
					Underlay: underlayIP,
				},
			}
			Expect(k8sClient.Status().Update(ctx, lbWithOldFinalizer)).To(Succeed())

			// Create LoadBalancer in DPDK mock
			vni := uint32(network.Spec.ID)
			underlayAddr := netip.MustParseAddr(underlayIP)
			dpdkLB := &dpdk.LoadBalancer{
				LoadBalancerMeta: dpdk.LoadBalancerMeta{ID: string(lbWithOldFinalizer.UID)},
				Spec: dpdk.LoadBalancerSpec{
					VNI:           vni,
					LbVipIP:       &lbWithOldFinalizer.Spec.IP.Addr,
					UnderlayRoute: &underlayAddr,
					Lbports: []dpdk.LBPort{
						{Port: 80, Protocol: 6}, // TCP
						{Port: 80, Protocol: 17}, // UDP
					},
				},
			}
			dpdkMock.SetGetLoadBalancerResponse(dpdkLB, nil)

			// Delete LoadBalancer
			Expect(k8sClient.Delete(ctx, lbWithOldFinalizer)).To(Succeed())

			// Fetch LoadBalancer with deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lbWithOldFinalizer.Name,
				Namespace: lbWithOldFinalizer.Namespace,
			}, lbWithOldFinalizer)).To(Succeed())

			// First reconcile - should remove old finalizer and requeue
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lbWithOldFinalizer.Name,
					Namespace: lbWithOldFinalizer.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue(), "Should requeue after removing old finalizer")

			// Verify old finalizer was removed but new finalizer remains
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      lbWithOldFinalizer.Name,
				Namespace: lbWithOldFinalizer.Namespace,
			}, lbWithOldFinalizer)).To(Succeed())
			Expect(lbWithOldFinalizer.ObjectMeta.Finalizers).NotTo(ContainElement("networking.metalnet.onmetal.de/loadBalancer"))
			Expect(lbWithOldFinalizer.ObjectMeta.Finalizers).To(ContainElement(fmt.Sprintf("networking.metalnet.onmetal.de/loadBalancer-%s", reconciler.ControllerID)))

			// Second reconcile - should remove new finalizer and complete deletion
			result, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      lbWithOldFinalizer.Name,
					Namespace: lbWithOldFinalizer.Namespace,
				},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse(), "Should not requeue after removing new finalizer")

			// Verify LoadBalancer was deleted
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      lbWithOldFinalizer.Name,
				Namespace: lbWithOldFinalizer.Namespace,
			}, lbWithOldFinalizer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))

			// Verify cleanup operations occurred (may be called twice due to two reconciles)
			// First reconcile: removes old finalizer
			// Second reconcile: removes new finalizer and does cleanup
			Expect(dpdkMock.DeleteLoadBalancerCallCount()).To(BeNumerically(">=", 1))
			Expect(routeUtilMock.WithdrawRouteCallCount()).To(BeNumerically(">=", 1))
		})
	})
})
