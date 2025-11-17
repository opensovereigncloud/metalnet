// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"net/netip"

	. "github.com/ironcore-dev/ironcore/utils/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("LoadBalancer Controller", Label("integration", "loadbalancer"), func() {
	ctx := SetupContext()
	ns := SetupTest(ctx)

	BeforeEach(func() {
		network = &metalnetv1alpha1.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-network",
				Namespace: ns.Name,
			},
			Spec: metalnetv1alpha1.NetworkSpec{
				ID:        123,
				PeeredIDs: []int32{2, 3},
				PeeredPrefixes: []metalnetv1alpha1.PeeredPrefix{
					{
						ID:       2,
						Prefixes: []metalnetv1alpha1.IPPrefix{},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, network)).To(Succeed())
		Expect(networkReconcile(ctx, *network)).To(Succeed())

		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())
			Expect(networkReconcile(ctx, *network)).To(Succeed())
		})
	})

	Context("Loadbalancer", Label("lb", "loadbalancer"), Ordered, func() {
		When("creating a Loadbalancer", func() {
			It("should create successfully", func() {
				// Defining and Creating Network is done in BeforeEach()

				// Define a new Loadbalancer object
				loadBalancer = &metalnetv1alpha1.LoadBalancer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-loadbalancer",
						Namespace: ns.Name,
					},
					Spec: metalnetv1alpha1.LoadBalancerSpec{
						NetworkRef: corev1.LocalObjectReference{Name: "test-network"},
						LBtype:     "Public",
						IPFamily:   corev1.IPv4Protocol,
						IP: metalnetv1alpha1.IP{
							Addr: netip.MustParseAddr("11.5.5.1"),
						},
						Ports: []metalnetv1alpha1.LBPort{
							{Protocol: "TCP", Port: 80},
							{Protocol: "UDP", Port: 80},
						},
						NodeName: &testNode,
					},
				}

				// Create the LoadBalancer object in k8s
				Expect(k8sClient.Create(ctx, loadBalancer)).To(Succeed())

				// Ensure it's created
				createdLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: ns.Name,
					Name:      "test-loadbalancer",
				}, createdLB)).To(Succeed())

				// requested LB and created LB should match
				Expect(createdLB).To(Equal(loadBalancer))

				// Finalizers should not yet be created
				Expect(createdLB.GetFinalizers()).To(BeNil())

				// LB should not yet be created in dpservice
				_, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).To(HaveOccurred())
			})

			It("should fail when already existing", func() {
				Expect(k8sClient.Create(ctx, loadBalancer)).ToNot(Succeed())
			})

			It("should reconcile successfully", func() {
				// Create and initialize loadbalancer reconciler
				Expect(lbReconcile(ctx, *loadBalancer)).To(Succeed())

				// Fetch the updated LB object from k8s
				fetchedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Name:      loadBalancer.Name,
					Namespace: loadBalancer.Namespace,
				}, fetchedLB)).To(Succeed())

				Expect(fetchedLB.GetFinalizers()).ToNot(BeZero())
				Expect(fetchedLB.Status.State).To(Equal(metalnetv1alpha1.LoadBalancerStateReady))

				// Fetch the LB object from dpservice
				dpdkLB, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).ToNot(HaveOccurred())

				// LB parameters in k8s and dpservice should match
				Expect(fetchedLB.Spec.IP.As4()).To(Equal(dpdkLB.Spec.LbVipIP.As4()))
				Expect(fetchedLB.Spec.Ports[0].Port).To(Equal(int32(dpdkLB.Spec.Lbports[0].Port)))

				// Fetch the VNI object from dpservice
				vniAvail, err := dpdkClient.GetVni(ctx, 123, uint8(dpdk.VniType_VNI_IPV4))
				Expect(err).NotTo(HaveOccurred())
				Expect(vniAvail.Spec.InUse).To(BeTrue())
				// Another reconcilition of network object is needed here. Because we dont have event watches in the test environment.
			})

			It("should update successfully", func() {
				// Update loadbalancer k8s object
				patchLB := loadBalancer.DeepCopy()
				patchLB.Spec.IP = metalnetv1alpha1.IP{
					Addr: netip.MustParseAddr("11.5.5.2"),
				}
				Expect(k8sClient.Patch(ctx, patchLB, client.MergeFrom(loadBalancer))).To(Succeed())

				Expect(lbReconcile(ctx, *loadBalancer)).To(Succeed())

				// Fetch updated k8s loadbalancer object
				updatedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Name:      loadBalancer.Name,
					Namespace: loadBalancer.Namespace,
				}, updatedLB)).To(Succeed())

				Expect(updatedLB.Spec.IP.Addr.String()).To(Equal("11.5.5.2"))
			})
		})

		When("deleting a Loadbalancer", Label("lb"), Ordered, func() {
			It("should delete successfully", func() {
				// Delete the Loadbalancer object from k8s
				Expect(k8sClient.Delete(ctx, loadBalancer)).To(Succeed())

				// Ensure it's deleted
				deletedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: ns.Name,
					Name:      loadBalancer.Name,
				}, deletedLB)).ToNot(Succeed())

				// LB should still be in dpservice
				_, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).ToNot(HaveOccurred())

				// Fetch the VNI object from dpservice
				vniAvail, err := dpdkClient.GetVni(ctx, 123, uint8(dpdk.VniType_VNI_IPV4))
				Expect(err).NotTo(HaveOccurred())
				Expect(vniAvail.Spec.InUse).To(BeTrue())
			})

			It("should reconcile successfully after delete", func() {
				// Create and initialize loadbalancer reconciler
				Expect(lbReconcile(ctx, *loadBalancer)).To(Succeed())

				// Fetch the deleted LB object from k8s
				fetchedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Name:      loadBalancer.Name,
					Namespace: loadBalancer.Namespace,
				}, fetchedLB)).ToNot(Succeed())

				// Fetch the deleted LB object from dpservice
				lb, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).To(HaveOccurred())
				Expect(lb.Status.Code).To(Equal(uint32(dpdkerrors.NOT_FOUND)))

				// Fetch the VNI object from dpservice
				vniAvail, err := dpdkClient.GetVni(ctx, 123, uint8(dpdk.VniType_VNI_IPV4))
				Expect(err).NotTo(HaveOccurred())
				Expect(vniAvail.Spec.InUse).To(BeFalse())
			})
		})
	})

	Context("Loadbalancer", Label("lb", "loadbalancer"), Ordered, func() {
		When("creating an ipv6 Loadbalancer", func() {
			It("should create successfully", func() {
				// Defining and Creating Network is done in BeforeEach()

				// Define a new Loadbalancer object
				loadBalancer = &metalnetv1alpha1.LoadBalancer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-ipv6-loadbalancer",
						Namespace: ns.Name,
					},
					Spec: metalnetv1alpha1.LoadBalancerSpec{
						NetworkRef: corev1.LocalObjectReference{Name: "test-network"},
						LBtype:     "Public",
						IPFamily:   corev1.IPv6Protocol,
						IP: metalnetv1alpha1.IP{
							Addr: netip.MustParseAddr("dede::01"),
						},
						Ports: []metalnetv1alpha1.LBPort{
							{Protocol: "TCP", Port: 80},
							{Protocol: "UDP", Port: 80},
						},
						NodeName: &testNode,
					},
				}

				// Create the LoadBalancer object in k8s
				Expect(k8sClient.Create(ctx, loadBalancer)).To(Succeed())

				// Ensure it's created
				createdLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: ns.Name,
					Name:      "test-ipv6-loadbalancer",
				}, createdLB)).To(Succeed())

				// requested LB and created LB should match
				Expect(createdLB).To(Equal(loadBalancer))

				// Finalizers should not yet be created
				Expect(createdLB.GetFinalizers()).To(BeNil())

				// LB should not yet be created in dpservice
				_, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).To(HaveOccurred())
			})

			It("should fail when already existing", func() {
				Expect(k8sClient.Create(ctx, loadBalancer)).ToNot(Succeed())
			})

			It("should reconcile successfully", func() {
				// Create and initialize loadbalancer reconciler
				Expect(lbReconcile(ctx, *loadBalancer)).To(Succeed())

				// Fetch the updated LB object from k8s
				fetchedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Name:      loadBalancer.Name,
					Namespace: loadBalancer.Namespace,
				}, fetchedLB)).To(Succeed())

				Expect(fetchedLB.GetFinalizers()).ToNot(BeZero())
				Expect(fetchedLB.Status.State).To(Equal(metalnetv1alpha1.LoadBalancerStateReady))

				// Fetch the LB object from dpservice
				dpdkLB, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).ToNot(HaveOccurred())

				// LB parameters in k8s and dpservice should match
				Expect(fetchedLB.Spec.IP.As16()).To(Equal(dpdkLB.Spec.LbVipIP.As16()))
				Expect(fetchedLB.Spec.Ports[0].Port).To(Equal(int32(dpdkLB.Spec.Lbports[0].Port)))

				// Fetch the VNI object from dpservice
				vniAvail, err := dpdkClient.GetVni(ctx, 123, uint8(dpdk.VniType_VNI_IPV6))
				Expect(err).NotTo(HaveOccurred())
				Expect(vniAvail.Spec.InUse).To(BeTrue())
				// Another reconcilition of network object is needed here. Because we dont have event watches in the test environment.
			})

			It("should update successfully", func() {
				// Update loadbalancer k8s object
				patchLB := loadBalancer.DeepCopy()
				patchLB.Spec.IP = metalnetv1alpha1.IP{
					Addr: netip.MustParseAddr("dede::2"),
				}
				Expect(k8sClient.Patch(ctx, patchLB, client.MergeFrom(loadBalancer))).To(Succeed())

				Expect(lbReconcile(ctx, *loadBalancer)).To(Succeed())

				// Fetch updated k8s loadbalancer object
				updatedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Name:      loadBalancer.Name,
					Namespace: loadBalancer.Namespace,
				}, updatedLB)).To(Succeed())

				Expect(updatedLB.Spec.IP.Addr.String()).To(Equal("dede::2"))
			})
		})

		When("deleting a Loadbalancer", Label("lb"), Ordered, func() {
			It("should delete successfully", func() {
				// Delete the Loadbalancer object from k8s
				Expect(k8sClient.Delete(ctx, loadBalancer)).To(Succeed())

				// Ensure it's deleted
				deletedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: ns.Name,
					Name:      loadBalancer.Name,
				}, deletedLB)).ToNot(Succeed())

				// LB should still be in dpservice
				_, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).ToNot(HaveOccurred())

				// Fetch the VNI object from dpservice
				vniAvail, err := dpdkClient.GetVni(ctx, 123, uint8(dpdk.VniType_VNI_IPV4))
				Expect(err).NotTo(HaveOccurred())
				Expect(vniAvail.Spec.InUse).To(BeTrue())
			})

			It("should reconcile successfully after delete", func() {
				// Create and initialize loadbalancer reconciler
				Expect(lbReconcile(ctx, *loadBalancer)).To(Succeed())

				// Fetch the deleted LB object from k8s
				fetchedLB := &metalnetv1alpha1.LoadBalancer{}
				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Name:      loadBalancer.Name,
					Namespace: loadBalancer.Namespace,
				}, fetchedLB)).ToNot(Succeed())

				// Fetch the deleted LB object from dpservice
				lb, err := dpdkClient.GetLoadBalancer(ctx, string(loadBalancer.ObjectMeta.UID))
				Expect(err).To(HaveOccurred())
				Expect(lb.Status.Code).To(Equal(uint32(dpdkerrors.NOT_FOUND)))

				// Fetch the VNI object from dpservice
				vniAvail, err := dpdkClient.GetVni(ctx, 123, uint8(dpdk.VniType_VNI_IPV4))
				Expect(err).NotTo(HaveOccurred())
				Expect(vniAvail.Spec.InUse).To(BeFalse())
			})
		})
	})
})
