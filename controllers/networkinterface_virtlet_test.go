package controllers

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("NetworkInterfaceReconciler Virtlet Machine UID", func() {
	var (
		ctx            context.Context
		ns             *corev1.Namespace
		network        *metalnetv1alpha1.Network
		reconciler     *NetworkInterfaceReconciler
		dpdkMock       *mocks.DPDKClientMock
		routeUtilMock  *mocks.RouteUtilMock
		netFnsMock     *mocks.NetFnsManagerMock
		virtletTestDir string
	)

	BeforeEach(func() {
		// Setup base test infrastructure
		ctx, ns, network, reconciler, dpdkMock, routeUtilMock, netFnsMock = setupNetworkInterfaceTest()

		// Create temp directory for virtlet machine UIDs
		var err error
		virtletTestDir, err = os.MkdirTemp("", "virtlet-test-*")
		Expect(err).NotTo(HaveOccurred())

		// Set the path in the reconciler
		reconciler.VirtletMachineUIDPath = virtletTestDir
	})

	AfterEach(func() {
		// Clean up test infrastructure
		cleanupNetworkInterfaceTest(ctx, ns, dpdkMock, routeUtilMock, netFnsMock)

		// Clean up temp directory
		if virtletTestDir != "" {
			os.RemoveAll(virtletTestDir)
		}
	})

	Context("Machine UID exists", func() {
		It("should remove deletion marks when machine UID directory exists", func() {
			machineUID := "test-machine-123"

			// Create machine UID directory
			machineDir := filepath.Join(virtletTestDir, machineUID)
			Expect(os.Mkdir(machineDir, 0755)).To(Succeed())

			// Create NIC with machine UID annotation and deletion marks
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-exists",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid":                      machineUID,
						"metalnet.onmetal.de/ok-to-delete":                    "true",
						"metalnet.onmetal.de/deletion-grace-period-timestamp": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.100")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify deletion marks were removed
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Annotations).NotTo(HaveKey("metalnet.onmetal.de/ok-to-delete"))
			Expect(nic.Annotations).NotTo(HaveKey("metalnet.onmetal.de/deletion-grace-period-timestamp"))
			Expect(nic.Annotations).To(HaveKey("virtlet.onmetal.de/machine-uid")) // Original annotation should remain
		})
	})

	Context("Machine UID missing", func() {
		It("should add deletion marks when machine UID directory does not exist", func() {
			machineUID := "test-machine-missing"

			// Do NOT create machine UID directory

			// Create NIC with machine UID annotation but no deletion marks
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-missing",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid": machineUID,
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.101")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify deletion marks were added
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Annotations).To(HaveKey("metalnet.onmetal.de/ok-to-delete"))
			Expect(nic.Annotations["metalnet.onmetal.de/ok-to-delete"]).To(Equal("true"))
			Expect(nic.Annotations).To(HaveKey("metalnet.onmetal.de/deletion-grace-period-timestamp"))

			// Verify grace period is ~24 hours from now
			gracePeriodStr := nic.Annotations["metalnet.onmetal.de/deletion-grace-period-timestamp"]
			gracePeriod, err := time.Parse(time.RFC3339, gracePeriodStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(gracePeriod).To(BeTemporally("~", time.Now().Add(24*time.Hour), 5*time.Second))
		})

		It("should delete NIC when grace period has elapsed", func() {
			machineUID := "test-machine-expired"

			// Do NOT create machine UID directory

			// Create NIC with machine UID annotation and EXPIRED grace period
			pastTime := time.Now().Add(-1 * time.Hour) // 1 hour ago
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-expired",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid":                      machineUID,
						"metalnet.onmetal.de/ok-to-delete":                    "true",
						"metalnet.onmetal.de/deletion-grace-period-timestamp": pastTime.Format(time.RFC3339),
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.102")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify NIC was deleted
			err := k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should continue normal deletion when grace period not elapsed", func() {
			machineUID := "test-machine-not-expired"

			// Do NOT create machine UID directory

			// Create NIC with machine UID annotation and future grace period
			futureTime := time.Now().Add(24 * time.Hour)
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-not-expired",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid":                      machineUID,
						"metalnet.onmetal.de/ok-to-delete":                    "true",
						"metalnet.onmetal.de/deletion-grace-period-timestamp": futureTime.Format(time.RFC3339),
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.103")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - should succeed and continue with normal deletion logic
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// NIC should still exist (not deleted)
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
		})
	})

	Context("Error handling", func() {
		It("should handle error reading virtlet directory", func() {
			machineUID := "test-machine-error"

			// Set invalid path to trigger read error
			reconciler.VirtletMachineUIDPath = "/nonexistent/path/that/does/not/exist"

			// Create NIC with machine UID annotation
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-error",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid": machineUID,
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.104")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error reading virtlet directory"))

			// Restore valid path for cleanup
			reconciler.VirtletMachineUIDPath = virtletTestDir
		})

		It("should handle invalid grace period timestamp", func() {
			machineUID := "test-machine-invalid-timestamp"

			// Do NOT create machine UID directory

			// Create NIC with invalid timestamp
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-invalid-ts",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid":                      machineUID,
						"metalnet.onmetal.de/ok-to-delete":                    "true",
						"metalnet.onmetal.de/deletion-grace-period-timestamp": "invalid-timestamp-format",
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.105")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile should fail
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing deletion grace period timestamp"))
		})
	})

	Context("Machine UID directory with files", func() {
		It("should only match directories not files in virtlet path", func() {
			machineUID := "test-machine-dir-only"

			// Create a FILE with the machine UID name (not a directory)
			machineFile := filepath.Join(virtletTestDir, machineUID)
			Expect(os.WriteFile(machineFile, []byte("test"), 0644)).To(Succeed())

			// Also create an unrelated directory
			unrelatedDir := filepath.Join(virtletTestDir, "other-machine")
			Expect(os.Mkdir(unrelatedDir, 0755)).To(Succeed())

			// Create NIC - should NOT find the machine UID (file doesn't count)
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-virtlet-file-not-dir",
					Namespace: ns.Name,
					Annotations: map[string]string{
						"virtlet.onmetal.de/machine-uid": machineUID,
					},
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("192.168.1.106")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Reconcile - should add deletion marks (machine UID not found as directory)
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify deletion marks were added
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}, nic)).To(Succeed())
			Expect(nic.Annotations).To(HaveKey("metalnet.onmetal.de/ok-to-delete"))
		})
	})
})
