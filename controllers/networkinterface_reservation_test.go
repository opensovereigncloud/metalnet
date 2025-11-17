// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"net/netip"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

var _ = Describe("NetworkInterfaceReconciler - IP Reservation Management", func() {
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

	Context("IP Reservation Management", func() {
		It("should create initial reservations when none exist", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-new-reservation",
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

			// Reconcile - should create reservation on first pass
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify reservation was created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation).NotTo(BeNil())
			Expect(nic.Status.Reservation.IPs).To(HaveLen(1))
			Expect(nic.Status.Reservation.IPs[0].Overlay).To(Equal("10.0.0.100"))
			Expect(nic.Status.Reservation.IPs[0].Underlay).NotTo(BeEmpty())
		})

		It("should preserve underlay IPs when overlay IPs don't change", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-preserve-underlay",
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

			// First reconcile - create initial reservation
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Get the initial underlay IP
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			initialUnderlayIP := nic.Status.Reservation.IPs[0].Underlay

			// Trigger another reconcile without changing spec
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse()) // Should not requeue if nothing changed

			// Verify underlay IP is preserved
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.IPs[0].Underlay).To(Equal(initialUnderlayIP))
		})

		It("should update reservation when IPs are added", func() {
			reconciler.EnableIPv6Support = true
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-add-ip",
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

			// Initial reconcile
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify initial state
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.IPs).To(HaveLen(1))
			initialUnderlayIP := nic.Status.Reservation.IPs[0].Underlay

			// Add IPv6 address
			nic.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
			nic.Spec.IPs = append(nic.Spec.IPs, metalnetv1alpha1.IP{Addr: netip.MustParseAddr("fd00:1234:5678::100")})
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should update reservation
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify reservation was updated
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.IPs).To(HaveLen(2))
			// Original underlay IP should be preserved
			Expect(nic.Status.Reservation.IPs[0].Underlay).To(Equal(initialUnderlayIP))
			// New IP should have new underlay
			Expect(nic.Status.Reservation.IPs[1].Overlay).To(Equal("fd00:1234:5678::100"))
			Expect(nic.Status.Reservation.IPs[1].Underlay).NotTo(BeEmpty())
		})

		It("should update reservation when VirtualIP is added", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-add-vip",
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

			// Initial reconcile without VirtualIP
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify initial state has no VirtualIP reservation
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.VirtualIP).To(BeNil())

			// Add VirtualIP
			vip := netip.MustParseAddr("10.0.0.200")
			nic.Spec.VirtualIP = &metalnetv1alpha1.IP{Addr: vip}
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should update reservation
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify VirtualIP reservation was created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.VirtualIP).NotTo(BeNil())
			Expect(nic.Status.Reservation.VirtualIP.Overlay).To(Equal("10.0.0.200"))
			Expect(nic.Status.Reservation.VirtualIP.Underlay).NotTo(BeEmpty())
		})

		It("should update reservation when NAT IP is added", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-add-nat",
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

			// Initial reconcile without NAT
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify initial state has no NAT IP reservation
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.NatIP).To(BeNil())

			// Add NAT IP
			natIP := netip.MustParseAddr("10.0.0.201")
			nic.Spec.NAT = &metalnetv1alpha1.NATDetails{IP: &metalnetv1alpha1.IP{Addr: natIP}, Port: 30000, EndPort: 30100}
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should update reservation
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify NAT IP reservation was created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.NatIP).NotTo(BeNil())
			Expect(nic.Status.Reservation.NatIP.Overlay).To(Equal("10.0.0.201"))
			Expect(nic.Status.Reservation.NatIP.Underlay).NotTo(BeEmpty())
		})

		It("should update reservation when Prefixes are added", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-add-prefix",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.105")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Initial reconcile without Prefixes
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify initial state has no Prefix reservations
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.Prefixes).To(HaveLen(0))

			// Add Prefix
			nic.Spec.Prefixes = []metalnetv1alpha1.IPPrefix{
				{Prefix: netip.MustParsePrefix("10.0.10.0/24")},
			}
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should update reservation
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify Prefix reservation was created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.Prefixes).To(HaveLen(1))
			Expect(nic.Status.Reservation.Prefixes[0].Overlay).To(Equal("10.0.10.0/24"))
			Expect(nic.Status.Reservation.Prefixes[0].Underlay).NotTo(BeEmpty())
		})

		It("should update reservation when LoadBalancerTargets are added", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-add-lb",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.106")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Initial reconcile without LoadBalancerTargets
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify initial state has no LB Target reservations
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.LoadBalancerTargets).To(HaveLen(0))

			// Add LoadBalancerTarget
			nic.Spec.LoadBalancerTargets = []metalnetv1alpha1.IPPrefix{
				{Prefix: netip.MustParsePrefix("10.0.20.0/24")},
			}
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should update reservation
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Verify LoadBalancerTarget reservation was created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.Reservation.LoadBalancerTargets).To(HaveLen(1))
			Expect(nic.Status.Reservation.LoadBalancerTargets[0].Overlay).To(Equal("10.0.20.0/24"))
			Expect(nic.Status.Reservation.LoadBalancerTargets[0].Underlay).NotTo(BeEmpty())
		})
	})
})
