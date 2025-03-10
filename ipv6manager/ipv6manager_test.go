package ipv6manager_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ironcore-dev/metalnet/ipv6manager"
)

func TestIPv6Manager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "IPv6Manager Suite")
}

var _ = Describe("IPv6Manager", func() {
	var manager *ipv6manager.IPv6Manager

	BeforeEach(func() {
		// Reset the instance for each test to ensure clean state
		ipv6manager.ResetForTest()
		manager = ipv6manager.GetInstance()
	})

	Context("Singleton pattern", func() {
		It("should always return the same instance when not reset", func() {
			// Skip reset for this test to verify true singleton behavior
			manager = ipv6manager.GetInstance()
			secondInstance := ipv6manager.GetInstance()
			Expect(manager).To(BeIdenticalTo(secondInstance))
		})
	})

	Context("Setting CIDR", func() {
		It("should accept a valid IPv6 CIDR", func() {
			err := manager.SetCIDR("2001:db8::/64")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should reject an invalid CIDR", func() {
			err := manager.SetCIDR("invalid-cidr")
			Expect(err).To(HaveOccurred())
		})

		It("should reject an IPv4 CIDR", func() {
			err := manager.SetCIDR("192.168.1.0/24")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not an IPv6 CIDR"))
		})
	})

	Context("Adding existing IPs", func() {
		BeforeEach(func() {
			err := manager.SetCIDR("2001:db8::/64")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should accept a valid IPv6 address within the CIDR", func() {
			err := manager.AddExistingIP("2001:db8::1")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should reject an invalid IP address", func() {
			err := manager.AddExistingIP("not-an-ip")
			Expect(err).To(HaveOccurred())
		})

		It("should reject an IPv4 address", func() {
			err := manager.AddExistingIP("192.168.1.1")
			Expect(err).To(HaveOccurred())
		})

		It("should reject an IPv6 address outside the CIDR", func() {
			err := manager.AddExistingIP("2001:db9::1") // Different prefix
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not within the CIDR"))
		})
	})

	Context("Generating random IPv6 addresses", func() {
		BeforeEach(func() {
			// Reset for each test
			ipv6manager.ResetForTest()
			manager = ipv6manager.GetInstance()
			err := manager.SetCIDR("2001:db8::/64")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a valid IPv6 address within the CIDR", func() {
			ip, err := manager.GenerateRandomIPv6()
			Expect(err).NotTo(HaveOccurred())
			Expect(ip).To(HavePrefix("2001:db8:"))
		})

		It("should generate unique addresses", func() {
			// Generate multiple addresses
			addresses := make(map[string]bool)
			for i := 0; i < 10; i++ {
				ip, err := manager.GenerateRandomIPv6()
				Expect(err).NotTo(HaveOccurred())

				// Ensure each address is unique
				Expect(addresses).NotTo(HaveKey(ip))
				addresses[ip] = true
			}
		})

		It("should not generate addresses that were added as existing", func() {
			existingIP := "2001:db8::1234"
			err := manager.AddExistingIP(existingIP)
			Expect(err).NotTo(HaveOccurred())

			// Generate multiple addresses and ensure none match the existing one
			for i := 0; i < 10; i++ {
				ip, err := manager.GenerateRandomIPv6()
				Expect(err).NotTo(HaveOccurred())
				Expect(ip).NotTo(Equal(existingIP))
			}
		})

		It("should fail when CIDR is not set", func() {
			// Create a new manager without setting CIDR
			newManager := ipv6manager.GetInstance()

			// Hack to reset the CIDR for testing (this wouldn't be possible in real usage)
			// Since we're testing with a singleton, we need to reset its state
			err := newManager.SetCIDR("")
			// This SetCIDR("") might fail depending on implementation
			// But we just want to ensure the CIDR is not set for this test

			ip, err := newManager.GenerateRandomIPv6()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeEmpty())
		})
	})

	Context("Getting existing IPs", func() {
		BeforeEach(func() {
			// Reset for each test
			ipv6manager.ResetForTest()
			manager = ipv6manager.GetInstance()
			err := manager.SetCIDR("2001:db8::/64")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return all added and generated IPs", func() {
			// Add some existing IPs
			existingIPs := []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"}
			for _, ip := range existingIPs {
				err := manager.AddExistingIP(ip)
				Expect(err).NotTo(HaveOccurred())
			}

			// Generate some IPs
			generatedIPs := make([]string, 0, 2)
			for i := 0; i < 2; i++ {
				ip, err := manager.GenerateRandomIPv6()
				Expect(err).NotTo(HaveOccurred())
				generatedIPs = append(generatedIPs, ip)
			}

			// Get all IPs
			allIPs := manager.GetExistingIPs()

			// Ensure all existing and generated IPs are included
			for _, ip := range existingIPs {
				Expect(allIPs).To(ContainElement(ip))
			}
			for _, ip := range generatedIPs {
				Expect(allIPs).To(ContainElement(ip))
			}

			// Ensure the count matches
			Expect(len(allIPs)).To(Equal(len(existingIPs) + len(generatedIPs)))
		})
	})

	Context("Edge cases", func() {
		BeforeEach(func() {
			// Reset for each test
			ipv6manager.ResetForTest()
			manager = ipv6manager.GetInstance()
			err := manager.SetCIDR("2001:db8::/64")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle a very small CIDR", func() {
			// Set a very small CIDR (only 4 addresses)
			err := manager.SetCIDR("2001:db8::/126")
			Expect(err).NotTo(HaveOccurred())

			// Add 3 of the 4 possible addresses
			err = manager.AddExistingIP("2001:db8::0")
			Expect(err).NotTo(HaveOccurred())
			err = manager.AddExistingIP("2001:db8::1")
			Expect(err).NotTo(HaveOccurred())
			err = manager.AddExistingIP("2001:db8::2")
			Expect(err).NotTo(HaveOccurred())

			// There should be one address left
			ip, err := manager.GenerateRandomIPv6()
			Expect(err).NotTo(HaveOccurred())
			Expect(ip).To(Equal("2001:db8::3"))

			// Now the space should be exhausted
			// This test depends on implementation details - it may retry many times
			// before failing, or immediately recognize the space is exhausted
			_, err = manager.GenerateRandomIPv6()
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Withdrawing IPs", func() {
		BeforeEach(func() {
			// Reset for each test
			ipv6manager.ResetForTest()
			manager = ipv6manager.GetInstance()
			err := manager.SetCIDR("2001:db8::/64")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should remove an existing IP", func() {
			// Add an IP
			existingIP := "2001:db8::1234"
			err := manager.AddExistingIP(existingIP)
			Expect(err).NotTo(HaveOccurred())

			// Verify IP is in the list
			ips := manager.GetExistingIPs()
			Expect(ips).To(ContainElement(existingIP))

			// Withdraw the IP
			manager.WithdrawIP(existingIP)

			// Verify IP is no longer in the list
			ips = manager.GetExistingIPs()
			Expect(ips).NotTo(ContainElement(existingIP))
		})

		It("should handle non-existent IPs gracefully", func() {
			// Withdraw an IP that doesn't exist
			nonExistentIP := "2001:db8::5678"

			// This should not panic or cause any errors
			manager.WithdrawIP(nonExistentIP)

			// Verify operation had no effect on existing IPs
			ips := manager.GetExistingIPs()
			Expect(len(ips)).To(Equal(0))
		})

		It("should handle invalid IP formats gracefully", func() {
			// Withdraw an invalid IP
			invalidIP := "not-an-ip"

			// This should not panic or cause any errors
			manager.WithdrawIP(invalidIP)
		})

		It("should allow reuse of withdrawn IPs", func() {
			// Generate an IP
			ip, err := manager.GenerateRandomIPv6()
			Expect(err).NotTo(HaveOccurred())

			// Withdraw the IP
			manager.WithdrawIP(ip)

			// Add the same IP manually
			err = manager.AddExistingIP(ip)
			Expect(err).NotTo(HaveOccurred())

			// Verify it's in the list again
			ips := manager.GetExistingIPs()
			Expect(ips).To(ContainElement(ip))
		})
	})

	Context("Computing IPv6 subnet /82", func() {
		It("should compute correct /82 subnets based on index", func() {
			// Test with a sample IPv6 base address
			baseIP := "2001:db8::"

			// Test for index 0
			subnet := ipv6manager.ComputeIPv6Subnet66(baseIP, 0)
			Expect(subnet).To(Equal("2001:db8:0:0:0:0000::/82"))

			// Test for index 1
			subnet = ipv6manager.ComputeIPv6Subnet66(baseIP, 1)
			Expect(subnet).To(Equal("2001:db8:0:0:0:4000::/82"))

			// Test for index 2
			subnet = ipv6manager.ComputeIPv6Subnet66(baseIP, 2)
			Expect(subnet).To(Equal("2001:db8:0:0:0:8000::/82"))

			// Test for index 3
			subnet = ipv6manager.ComputeIPv6Subnet66(baseIP, 3)
			Expect(subnet).To(Equal("2001:db8:0:0:0:c000::/82"))
		})

		It("should return empty string for invalid inputs", func() {
			// Test with invalid IPv6 address
			subnet := ipv6manager.ComputeIPv6Subnet66("invalid", 0)
			Expect(subnet).To(BeEmpty())

			// Test with negative index
			subnet = ipv6manager.ComputeIPv6Subnet66("2001:db8::", -1)
			Expect(subnet).To(BeEmpty())
		})
	})
})
