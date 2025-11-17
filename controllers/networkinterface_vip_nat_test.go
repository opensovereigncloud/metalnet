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

var _ = Describe("NetworkInterfaceReconciler - VirtualIP and NAT", func() {
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

	Context("VirtualIP functionality", func() {
		It("should create and delete VirtualIP when spec changes", func() {
			// Create NetworkInterface with VirtualIP
			virtualIP := netip.MustParseAddr("10.99.99.99")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtualip",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.10")},
					},
					VirtualIP: &metalnetv1alpha1.IP{Addr: virtualIP},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - creates reservation and interface
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify VirtualIP was created via DPDK
			Expect(dpdkMock.CreateVirtualIPCallCount()).To(BeNumerically(">", 0))

			// Verify VirtualIP status was set
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.VirtualIP).ToNot(BeNil())
			Expect(nic.Status.VirtualIP.Addr).To(Equal(virtualIP))

			// Now remove VirtualIP from spec
			nic.Spec.VirtualIP = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should delete VirtualIP
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify DeleteVirtualIP was called
			Expect(dpdkMock.DeleteVirtualIPCallCount()).To(BeNumerically(">", 0))

			// Verify status VirtualIP was cleared
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.VirtualIP).To(BeNil())
		})
	})

	Context("NAT functionality", func() {
		It("should create and delete NAT when spec changes", func() {
			// Create NetworkInterface with NAT
			natIP := netip.MustParseAddr("203.0.113.10")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-nat",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.10.10")},
					},
					NAT: &metalnetv1alpha1.NATDetails{
						IP:      &metalnetv1alpha1.IP{Addr: natIP},
						Port:    30000,
						EndPort: 30100,
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - creates reservation and interface
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify NAT was created via DPDK
			Expect(dpdkMock.CreateNatCallCount()).To(BeNumerically(">", 0))

			// Verify NAT status was set
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.NatIP).ToNot(BeNil())
			Expect(nic.Status.NatIP.IP.Addr).To(Equal(natIP))

			// Now remove NAT from spec
			nic.Spec.NAT = nil
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should delete NAT
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify DeleteNat was called
			Expect(dpdkMock.DeleteNatCallCount()).To(BeNumerically(">", 0))

			// Verify status NAT was cleared
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.NatIP).To(BeNil())
		})

		It("should not recreate NAT when it's already up-to-date", func() {
			// Create NetworkInterface with NAT
			natIP := netip.MustParseAddr("203.0.113.20")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-nat-update",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.10.20")},
					},
					NAT: &metalnetv1alpha1.NATDetails{
						IP:      &metalnetv1alpha1.IP{Addr: natIP},
						Port:    31000,
						EndPort: 31100,
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - creates NAT
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Record initial call counts
			initialCreateCount := dpdkMock.CreateNatCallCount()
			initialDeleteCount := dpdkMock.DeleteNatCallCount()

			// Second reconcile - NAT is already up-to-date, should not recreate
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify NAT was not recreated (create/delete counts should be unchanged)
			Expect(dpdkMock.CreateNatCallCount()).To(Equal(initialCreateCount), "NAT should not be recreated")
			Expect(dpdkMock.DeleteNatCallCount()).To(Equal(initialDeleteCount), "NAT should not be deleted")

			// Verify status is still correct
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.NatIP).ToNot(BeNil())
			Expect(nic.Status.NatIP.IP.Addr).To(Equal(natIP))
		})

		It("should update NAT when IP changes", func() {
			// Create NetworkInterface with NAT
			initialNatIP := netip.MustParseAddr("203.0.113.30")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-nat-ip-change",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.10.30")},
					},
					NAT: &metalnetv1alpha1.NATDetails{
						IP:      &metalnetv1alpha1.IP{Addr: initialNatIP},
						Port:    32000,
						EndPort: 32100,
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - creates NAT
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Record call counts after initial creation
			createCountAfterInit := dpdkMock.CreateNatCallCount()
			deleteCountAfterInit := dpdkMock.DeleteNatCallCount()

			// Fetch latest version before updating (status was modified by reconciler)
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())

			// Update NAT IP
			newNatIP := netip.MustParseAddr("203.0.113.31")
			nic.Spec.NAT.IP.Addr = newNatIP
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should delete old NAT and create new one
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify NAT was deleted and recreated
			Expect(dpdkMock.DeleteNatCallCount()).To(BeNumerically(">", deleteCountAfterInit), "Old NAT should be deleted")
			Expect(dpdkMock.CreateNatCallCount()).To(BeNumerically(">", createCountAfterInit), "New NAT should be created")

			// Verify status reflects new NAT IP
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.NatIP).ToNot(BeNil())
			Expect(nic.Status.NatIP.IP.Addr).To(Equal(newNatIP))
		})

		It("should update NAT when port range changes", func() {
			// Create NetworkInterface with NAT
			natIP := netip.MustParseAddr("203.0.113.40")
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-nat-port-change",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.10.40")},
					},
					NAT: &metalnetv1alpha1.NATDetails{
						IP:      &metalnetv1alpha1.IP{Addr: natIP},
						Port:    33000,
						EndPort: 33100,
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// First reconcile - creates NAT
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Record call counts after initial creation
			createCountAfterInit := dpdkMock.CreateNatCallCount()
			deleteCountAfterInit := dpdkMock.DeleteNatCallCount()

			// Fetch latest version before updating (status was modified by reconciler)
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())

			// Update NAT port range
			nic.Spec.NAT.Port = 34000
			nic.Spec.NAT.EndPort = 34200
			Expect(k8sClient.Update(ctx, nic)).To(Succeed())

			// Reconcile - should delete old NAT and create new one
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify NAT was deleted and recreated
			Expect(dpdkMock.DeleteNatCallCount()).To(BeNumerically(">", deleteCountAfterInit), "Old NAT should be deleted")
			Expect(dpdkMock.CreateNatCallCount()).To(BeNumerically(">", createCountAfterInit), "New NAT should be created")

			// Verify status still shows NAT IP (port range isn't in status)
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Status.NatIP).ToNot(BeNil())
			Expect(nic.Status.NatIP.IP.Addr).To(Equal(natIP))
		})
	})
})
