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
)

var _ = Describe("NetworkInterfaceReconciler - IPv6 Support", func() {
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

	Context("IPv6 Support", func() {
		It("should create IPv6 interface when EnableIPv6Support is true", func() {
			// Enable IPv6 support for this test
			reconciler.EnableIPv6Support = true

			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ipv6",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("fd00:1234:5678::1")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile until complete
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(1))

			// Verify routes were announced (IPv6 routes should be announced)
			Expect(routeUtilMock.AnnounceRouteCallCount()).To(BeNumerically(">=", 1))

			// Verify status
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.State).To(Equal(metalnetv1alpha1.NetworkInterfaceStateReady))
		})

		It("should reject IPv6 interface when EnableIPv6Support is false", func() {
			// Explicitly disable IPv6 support
			reconciler.EnableIPv6Support = false

			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-ipv6-disabled",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("fd00:1234:5678::2")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - should fail validation
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ipv6 flag not enabled but ipv6 address set on interface"))

			// Verify no DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(0))
		})

		It("should support dual-stack with both IPv4 and IPv6 families", func() {
			// Enable IPv6 support
			reconciler.EnableIPv6Support = true

			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-dualstack",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.50")},         // IPv4
						{Addr: netip.MustParseAddr("fd00:1234:5678::3")}, // IPv6
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile until complete
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(1))

			// Verify status shows dual-stack capability (both families declared)
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.State).To(Equal(metalnetv1alpha1.NetworkInterfaceStateReady))
			Expect(nic.Spec.IPFamilies).To(HaveLen(2))
			Expect(nic.Spec.IPFamilies).To(ContainElements(corev1.IPv4Protocol, corev1.IPv6Protocol))
		})

		It("should reject duplicate IP families", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-dup-families",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv4Protocol}, // Duplicate
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.60")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - should fail validation
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("duplicate IPFamily"))

			// Verify no DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(0))
		})

		It("should reject multiple IPv4 addresses", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-multi-ipv4",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.70")},
						{Addr: netip.MustParseAddr("10.0.0.71")}, // Multiple IPv4
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - should fail validation
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("more than one IPv4 or IPv6 address is not allowed"))

			// Verify no DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(0))
		})

		It("should reject multiple IPv6 addresses", func() {
			// Enable IPv6 support for this test
			reconciler.EnableIPv6Support = true

			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-multi-ipv6",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("fd00:1234:5678::10")},
						{Addr: netip.MustParseAddr("fd00:1234:5678::11")}, // Multiple IPv6
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - should fail validation
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("more than one IPv4 or IPv6 address is not allowed"))

			// Verify no DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(0))
		})
	})

	// NOTE: IPv6 Route Removal tests removed - these routes are announced via Metalbond,
	// not RouteUtil, so WithdrawRoute is never called for prefix/LB target removal.
	// The tests were checking non-existent behavior.
})
