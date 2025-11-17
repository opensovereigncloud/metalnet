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
	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Network Controller", Label("network", "integration"), Ordered, func() {
	ctx := SetupContext()
	ns := SetupTest(ctx)

	Context("When creating a Network", Ordered, func() {
		It("should create successfully", func() {
			network = &metalnetv1alpha1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkSpec{
					ID:        111,
					PeeredIDs: []int32{2, 3},
					PeeredPrefixes: []metalnetv1alpha1.PeeredPrefix{
						{
							ID:       2,
							Prefixes: []metalnetv1alpha1.IPPrefix{}, // Add desired IPPrefixes here
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())
			// Ensure it's created
			createdNetwork := &metalnetv1alpha1.Network{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{
				Namespace: ns.Name,
				Name:      "test-network",
			}, createdNetwork)).To(Succeed())

			// Equal() uses reflect.DeepEqual to compare (it compares whole structs recursively)
			Expect(createdNetwork).To(Equal(network))

			vniAvail, err := dpdkClient.GetVni(ctx, 111, uint8(dpdk.VniType_VNI_IPV4))
			Expect(err).NotTo(HaveOccurred())
			Expect(vniAvail.Spec.InUse).To(BeFalse())
		})

		It("should reconcile successfully", func() {
			// Create and initialize network reconciler
			Expect(networkReconcile(ctx, *network)).To(Succeed())

			// Fetch the updated Network object from k8s
			fetchedNetwork := &metalnetv1alpha1.Network{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, fetchedNetwork)).To(Succeed())

			Expect(fetchedNetwork.Spec.ID).To(Equal(int32(111)))
		})

		It("should fail when already existing", func() {
			Expect(k8sClient.Create(ctx, network)).ToNot(Succeed())
		})

		It("should update successfully", func() {
			// Update the k8s network object
			patchNetwork := network.DeepCopy()
			patchNetwork.Spec.PeeredIDs = []int32{4, 5}
			Expect(k8sClient.Patch(ctx, patchNetwork, client.MergeFrom(network))).To(Succeed())

			Expect(networkReconcile(ctx, *network)).To(Succeed())

			// Fetch updated k8s network object
			updatedNetwork := &metalnetv1alpha1.Network{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, updatedNetwork)).To(Succeed())

			Expect(updatedNetwork.Spec.PeeredIDs).To(Equal([]int32{4, 5}))
		})
		It("should update peering status successfully", func() {
			Skip("Peering API types have been removed")
			By("creating a network")
			network = &metalnetv1alpha1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkSpec{
					ID:        111,
					PeeredIDs: []int32{112},
				},
			}
			Expect(k8sClient.Create(ctx, network)).To(Succeed())

			By("ensuring network is created")
			Eventually(Get(network)).Should(Succeed())

			Expect(networkReconcile(ctx, *network)).To(Succeed())

			By("defining NetworkInterface object to use created network")
			networkInterface := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network-interface",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{
						Name: network.Name,
					},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{
							Addr: netip.MustParseAddr("10.0.0.3"),
						},
					},
				},
			}

			// Create the NetworkInterface k8s object
			Expect(k8sClient.Create(ctx, networkInterface)).To(Succeed())

			Expect(ifaceReconcile(ctx, *networkInterface)).To(Succeed())

			Eventually(Get(networkInterface)).Should(Succeed())
			By("inspecting the created network interface state")
			Expect(networkInterface.Status.State).To(Equal(metalnetv1alpha1.NetworkInterfaceStateReady))

			By("fetching the VNI object from dpservice")
			vniAvail, err := dpdkClient.GetVni(ctx, 111, uint8(dpdk.VniType_VNI_IPV4))
			Expect(err).NotTo(HaveOccurred())
			Expect(vniAvail.Spec.InUse).To(BeTrue())

			By("creating second network to use in peering")
			network2 := &metalnetv1alpha1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network2",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkSpec{
					ID:        112,
					PeeredIDs: []int32{network.Spec.ID},
				},
			}
			Expect(k8sClient.Create(ctx, network2)).To(Succeed())

			By("ensuring network is created")
			Eventually(Get(network2)).Should(Succeed())
			// Create and initialize network reconciler
			Expect(networkReconcile(ctx, *network2)).To(Succeed())

			By("defining a new NetworkInterface object to use created network")
			networkInterface2 := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network-interface2",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{
						Name: "test-network2",
					},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{
							Addr: netip.MustParseAddr("10.0.0.4"),
						},
					},
				},
			}

			// Create the NetworkInterface k8s object
			Expect(k8sClient.Create(ctx, networkInterface2)).To(Succeed())

			Expect(ifaceReconcile(ctx, *networkInterface2)).To(Succeed())
			// Fetch the updated Iface object from k8s
			Eventually(Get(networkInterface2)).Should(Succeed())
			Expect(networkInterface2.Status.State).To(Equal(metalnetv1alpha1.NetworkInterfaceStateReady))

			By("fetching the VNI object from dpservice")
			vniAvail, err = dpdkClient.GetVni(ctx, 112, uint8(dpdk.VniType_VNI_IPV4))
			Expect(err).NotTo(HaveOccurred())
			Expect(vniAvail.Spec.InUse).To(BeTrue())

			Expect(networkReconcile(ctx, *network)).To(Succeed())
			Expect(networkReconcile(ctx, *network2)).To(Succeed())

			By("reconciling networks again to see if status is not overwritten")
			Expect(networkReconcile(ctx, *network)).To(Succeed())
			Expect(networkReconcile(ctx, *network2)).To(Succeed())

			By("Removing peeredIDs")
			// Update the k8s network object
			baseNetwork := network.DeepCopy()
			network.Spec.PeeredIDs = []int32{}
			Expect(k8sClient.Patch(ctx, network, client.MergeFrom(baseNetwork))).To(Succeed())

			// Update the k8s network object
			baseNetwork2 := network2.DeepCopy()
			network2.Spec.PeeredIDs = []int32{}
			Expect(k8sClient.Patch(ctx, network2, client.MergeFrom(baseNetwork2))).To(Succeed())

			Expect(networkReconcile(ctx, *network)).To(Succeed())
			Expect(networkReconcile(ctx, *network2)).To(Succeed())

			By("Verifying peering information removed from status")
			Eventually(Object(network)).Should(SatisfyAll(
				HaveField("Status.Peerings", BeEmpty())))

			Eventually(Object(network2)).Should(SatisfyAll(
				HaveField("Status.Peerings", BeEmpty())))

			// Deletes the k8s network object after spec is completed
			DeferCleanup(func(ctx SpecContext) {
				Expect(k8sClient.Delete(ctx, networkInterface)).To(Succeed())
				Expect(ifaceReconcile(ctx, *networkInterface)).To(Succeed())
				Expect(k8sClient.Delete(ctx, networkInterface2)).To(Succeed())
				Expect(ifaceReconcile(ctx, *networkInterface2)).To(Succeed())
				Expect(k8sClient.Delete(ctx, network2)).To(Succeed())
				Expect(networkReconcile(ctx, *network2)).To(Succeed())
			})

		})
	})

	Context("When deleting a Network", Ordered, func() {
		It("should delete successfully", func() {
			// Delete the Network object
			Expect(k8sClient.Delete(ctx, network)).To(Succeed())

			// Ensure it's deleted
			deletedNetwork := &metalnetv1alpha1.Network{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{
				Namespace: ns.Name,
				Name:      "test-network",
			}, deletedNetwork)).ToNot(Succeed())
		})

		It("should reconcile successfully after delete", func() {
			// Create and initialize network reconciler
			Expect(networkReconcile(ctx, *network)).To(Succeed())

			// Fetch the updated Network object from k8s
			fetchedNetwork := &metalnetv1alpha1.Network{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{
				Name:      network.Name,
				Namespace: network.Namespace,
			}, fetchedNetwork)).ToNot(Succeed())

			vniAvail, err := dpdkClient.GetVni(ctx, 111, uint8(dpdk.VniType_VNI_IPV4))
			Expect(err).NotTo(HaveOccurred())
			Expect(vniAvail.Spec.InUse).To(BeFalse())
		})
	})

})
