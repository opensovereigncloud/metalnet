// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	"github.com/ironcore-dev/metalnet/sysfs"
	"github.com/jaypipes/ghw"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("NetworkInterfaceReconciler - DPDK Device Conversion", func() {
	var (
		ctx           context.Context
		ns            *corev1.Namespace
		network       *metalnetv1alpha1.Network
		reconciler    *NetworkInterfaceReconciler
		dpdkMock      *mocks.DPDKClientMock
		routeUtilMock *mocks.RouteUtilMock
		netFnsMock    *mocks.NetFnsManagerMock
		tempSysfsDir  string
	)

	BeforeEach(func() {
		ctx, ns, network, reconciler, dpdkMock, routeUtilMock, netFnsMock = setupNetworkInterfaceTest()
	})

	AfterEach(func() {
		// Clean up temporary sysfs directory if it was created
		if tempSysfsDir != "" {
			_ = os.RemoveAll(tempSysfsDir)
			tempSysfsDir = ""
		}
		cleanupNetworkInterfaceTest(ctx, ns, dpdkMock, routeUtilMock, netFnsMock)
	})

	Context("Tap Device Handling", func() {
		It("should pass through tap device string without conversion", func() {
			// Create a tap device PCI address
			tapAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "tap:0",
				Function: "0",
			}

			// Call convertToDPDKDevice directly
			deviceString, err := reconciler.convertToDPDKDevice(tapAddr)
			Expect(err).NotTo(HaveOccurred())
			// Tap devices should have colons and dots removed: "tap:0" -> "tap0"
			Expect(deviceString).To(Equal("tap0"))
		})

		It("should handle tap device with complex naming", func() {
			tapAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "tap:device.1",
				Function: "0",
			}

			deviceString, err := reconciler.convertToDPDKDevice(tapAddr)
			Expect(err).NotTo(HaveOccurred())
			// Should remove colons and dots: "tap:device.1" -> "tapdevice1"
			Expect(deviceString).To(Equal("tapdevice1"))
		})
	})

	Context("PCI Address Parsing Errors", func() {
		It("should handle invalid PCI function format", func() {
			// Create network interface with invalid PCI function
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-invalid-function",
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

			// Setup NetFns mock with invalid PCI function (octal parsing will fail)
			invalidAddr := &ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "00",
				Function: "9", // Invalid octal digit (octal is 0-7)
			}
			netFnsMock.PreClaim(nic.UID, invalidAddr)

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				IPs: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.0.0.100", Underlay: "192.168.1.20"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Reconcile should fail with parse error
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing address function"))
		})

		It("should handle invalid PCI device format", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-invalid-device",
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

			// Setup NetFns mock with invalid PCI device (hex parsing will fail)
			invalidAddr := &ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "gg", // Invalid hex characters
				Function: "0",
			}
			netFnsMock.PreClaim(nic.UID, invalidAddr)

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				IPs: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.0.0.101", Underlay: "192.168.1.21"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Reconcile should fail with parse error
			err := reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing address device"))
		})
	})

	Context("Multiport Eswitch Mode", func() {
		It("should use multiport device string format when enabled", func() {
			// Enable multiport eswitch mode
			reconciler.MultiportEswitchMode = true
			reconciler.PfToVfOffset = 0

			// Create a normal PCI address (not tap)
			pciAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "00",
				Function: "1",
			}

			// Call convertToDPDKDevice directly (without SysFS, it should use the fallback path)
			deviceString, err := reconciler.convertToDPDKDevice(pciAddr)
			Expect(err).NotTo(HaveOccurred())
			// Multiport format: {domain}:{bus}:00.0_representor_c0pf0vf{function}
			// Device 00 (hex) = 0, Function 1 (octal) = 1, so pciFunction = 0*8 + 1 = 1
			Expect(deviceString).To(Equal("0000:01:00.0_representor_c0pf0vf1"))
		})

		It("should use standard device string format when multiport disabled", func() {
			// Disable multiport eswitch mode
			reconciler.MultiportEswitchMode = false
			reconciler.PfToVfOffset = 0

			pciAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "00",
				Function: "1",
			}

			deviceString, err := reconciler.convertToDPDKDevice(pciAddr)
			Expect(err).NotTo(HaveOccurred())
			// Standard format: {domain}:{bus}:00.0_representor_vf{function}
			Expect(deviceString).To(Equal("0000:01:00.0_representor_vf1"))
		})

		It("should apply PfToVfOffset correctly in multiport mode", func() {
			reconciler.MultiportEswitchMode = true
			reconciler.PfToVfOffset = 2

			pciAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "02",
				Device:   "01",
				Function: "3",
			}

			deviceString, err := reconciler.convertToDPDKDevice(pciAddr)
			Expect(err).NotTo(HaveOccurred())
			// Device 01 (hex) = 1, Function 3 (octal) = 3, so pciFunction = 1*8 + 3 = 11
			// With offset 2: 11 - 2 = 9
			Expect(deviceString).To(Equal("0000:02:00.0_representor_c0pf0vf9"))
		})
	})

	Context("SysFS Physical Function Path Resolution", func() {
		var sysFSRoot string

		BeforeEach(func() {
			// Create temporary directory for mock sysfs
			var err error
			sysFSRoot, err = os.MkdirTemp("", "metalnet-sysfs-test-*")
			Expect(err).NotTo(HaveOccurred())
			tempSysfsDir = sysFSRoot

			// Create the FS and assign to reconciler
			fs, err := sysfs.NewFS(sysFSRoot)
			Expect(err).NotTo(HaveOccurred())
			reconciler.SysFS = fs
		})

		It("should resolve VF device to physical function PCI address", func() {
			// Setup mock sysfs structure for VF device
			pfAddr := "0000:01:00.0"
			vfAddr := "0000:01:00.1"

			// Create PCI device directories
			pfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", pfAddr)
			vfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", vfAddr)
			Expect(os.MkdirAll(pfDevPath, 0755)).To(Succeed())
			Expect(os.MkdirAll(vfDevPath, 0755)).To(Succeed())

			// Create physfn symlink from VF to PF
			physfnPath := filepath.Join(vfDevPath, "physfn")
			Expect(os.Symlink(pfDevPath, physfnPath)).To(Succeed())

			// Create SRIOV files in PF directory
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_numvfs"), []byte("4"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_totalvfs"), []byte("8"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_offset"), []byte("0"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_stride"), []byte("1"), 0644)).To(Succeed())

			// Disable multiport mode for this test
			reconciler.MultiportEswitchMode = false

			// Parse VF address
			vfPCIAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "01",
				Device:   "00",
				Function: "1",
			}

			// Call convertToDPDKDevice
			deviceString, err := reconciler.convertToDPDKDevice(vfPCIAddr)
			Expect(err).NotTo(HaveOccurred())
			// Should use PF address (00), not VF address
			// Device 00 (hex) = 0, Function 1 (octal) = 1, pciFunction = 0*8 + 1 = 1
			// With SRIOV offset 0: 1 - 0 = 1
			Expect(deviceString).To(Equal("0000:01:00.0_representor_vf1"))
		})

		It("should use multiport format with physfn resolution", func() {
			// Setup mock sysfs structure
			pfAddr := "0000:02:00.0"
			vfAddr := "0000:02:00.2"

			pfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", pfAddr)
			vfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", vfAddr)
			Expect(os.MkdirAll(pfDevPath, 0755)).To(Succeed())
			Expect(os.MkdirAll(vfDevPath, 0755)).To(Succeed())

			physfnPath := filepath.Join(vfDevPath, "physfn")
			Expect(os.Symlink(pfDevPath, physfnPath)).To(Succeed())

			// Create SRIOV files
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_numvfs"), []byte("8"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_totalvfs"), []byte("16"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_offset"), []byte("1"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(pfDevPath, "sriov_stride"), []byte("1"), 0644)).To(Succeed())

			// Enable multiport mode
			reconciler.MultiportEswitchMode = true

			vfPCIAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "02",
				Device:   "00",
				Function: "2",
			}

			deviceString, err := reconciler.convertToDPDKDevice(vfPCIAddr)
			Expect(err).NotTo(HaveOccurred())
			// Device 00 (hex) = 0, Function 2 (octal) = 2, pciFunction = 0*8 + 2 = 2
			// With SRIOV offset 1: 2 - 1 = 1
			Expect(deviceString).To(Equal("0000:02:00.0_representor_c0pf0vf1"))
		})

		It("should handle missing physfn gracefully", func() {
			// Create VF device without physfn symlink
			vfAddr := "0000:03:00.1"
			vfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", vfAddr)
			Expect(os.MkdirAll(vfDevPath, 0755)).To(Succeed())

			// No physfn symlink created

			vfPCIAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "03",
				Device:   "00",
				Function: "1",
			}

			// Should return error when trying to read physfn
			_, err := reconciler.convertToDPDKDevice(vfPCIAddr)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error getting sysfs physfn"))
		})

		It("should handle missing SRIOV information gracefully", func() {
			// Setup VF with physfn but no SRIOV files
			pfAddr := "0000:04:00.0"
			vfAddr := "0000:04:00.1"

			pfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", pfAddr)
			vfDevPath := filepath.Join(sysFSRoot, "bus", "pci", "devices", vfAddr)
			Expect(os.MkdirAll(pfDevPath, 0755)).To(Succeed())
			Expect(os.MkdirAll(vfDevPath, 0755)).To(Succeed())

			physfnPath := filepath.Join(vfDevPath, "physfn")
			Expect(os.Symlink(pfDevPath, physfnPath)).To(Succeed())

			// Don't create SRIOV files

			vfPCIAddr := ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "04",
				Device:   "00",
				Function: "1",
			}

			// Should return error when trying to read SRIOV info
			_, err := reconciler.convertToDPDKDevice(vfPCIAddr)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error getting sysfs sriov"))
		})
	})

	Context("Integration Test - Full Reconciliation with Device Conversion", func() {
		It("should successfully create interface with valid PCI address conversion", func() {
			nic := &metalnetv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-nic-pci-conversion",
					Namespace: ns.Name,
				},
				Spec: metalnetv1alpha1.NetworkInterfaceSpec{
					NetworkRef: corev1.LocalObjectReference{Name: network.Name},
					NodeName:   &testNode,
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					IPs: []metalnetv1alpha1.IP{
						{Addr: netip.MustParseAddr("10.0.0.110")},
					},
				},
			}
			Expect(k8sClient.Create(ctx, nic)).To(Succeed())

			// Setup valid PCI address
			pciAddr := &ghw.PCIAddress{
				Domain:   "0000",
				Bus:      "05",
				Device:   "02",
				Function: "3",
			}
			netFnsMock.PreClaim(nic.UID, pciAddr)

			// Setup status with reservation
			nic.Status.Reservation = &metalnetv1alpha1.NetworkInterfaceReservation{
				IPs: []metalnetv1alpha1.IPReservation{
					{Overlay: "10.0.0.110", Underlay: "192.168.1.30"},
				},
			}
			Expect(k8sClient.Status().Update(ctx, nic)).To(Succeed())

			// Reconcile should succeed
			Expect(reconcileUntilDone(reconciler, nic.Name, nic.Namespace, ctx)).To(Succeed())

			// Verify DPDK interface was created
			Expect(dpdkMock.CreateInterfaceCallCount()).To(Equal(1))

			// Verify the device string used in creation
			// Device 02 (hex) = 2, Function 3 (octal) = 3, pciFunction = 2*8 + 3 = 19
			// With default offset 0: 19 - 0 = 19
			// Should be in format: 0000:05:00.0_representor_vf19 (multiport disabled by default in setup)
			createArgs := dpdkMock.GetCreateInterfaceArgs()
			Expect(createArgs).To(HaveLen(1))
			Expect(createArgs[0].Spec.Device).To(Equal("0000:05:00.0_representor_vf19"))
		})
	})
})
