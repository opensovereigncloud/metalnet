// Package ipv6manager provides a singleton manager for IPv6 addresses.
// It keeps track of existing IPv6 addresses and generates unique random
// IPv6 addresses within a specified CIDR block.
package ipv6manager

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

// IPv6Manager is a singleton that manages IPv6 addresses
type IPv6Manager struct {
	mu          sync.Mutex
	existingIPs map[string]bool
	cidr        *net.IPNet
	prefixLen   int
}

var (
	instance *IPv6Manager
	once     sync.Once
	// For test purposes
	resetForTest = false
)

// GetInstance returns the singleton instance of IPv6Manager
func GetInstance() *IPv6Manager {
	if resetForTest {
		resetForTest = false
		instance = &IPv6Manager{
			existingIPs: make(map[string]bool),
		}
		return instance
	}

	once.Do(func() {
		instance = &IPv6Manager{
			existingIPs: make(map[string]bool),
		}
	})
	return instance
}

// ResetForTest resets the singleton instance for testing purposes
// This should only be used in tests
func ResetForTest() {
	resetForTest = true
}

// SetCIDR sets the CIDR block as the base for IPv6 generation
// This also resets the existing IPs map to avoid issues with changing CIDRs
func (m *IPv6Manager) SetCIDR(cidrStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// For empty string (used in tests), just clear the CIDR
	if cidrStr == "" {
		m.cidr = nil
		m.prefixLen = 0
		m.existingIPs = make(map[string]bool)
		return nil
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Ensure it's an IPv6 CIDR
	if len(ipNet.IP) != net.IPv6len {
		return fmt.Errorf("not an IPv6 CIDR: %s", cidrStr)
	}

	m.cidr = ipNet

	// Get prefix length
	prefixLen, _ := ipNet.Mask.Size()
	m.prefixLen = prefixLen

	// Reset the existingIPs map when changing CIDR
	m.existingIPs = make(map[string]bool)

	return nil
}

// AddExistingIP adds an existing IPv6 address to the manager
// Only adds the IP if it's within the configured CIDR
func (m *IPv6Manager) AddExistingIP(ipStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IPv6 address: %s", ipStr)
	}

	// Check if it's an IPv4 address (IPv4 addresses will have a length of 4 when using To4())
	if ip.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %s", ipStr)
	}

	// Ensure it's an IPv6 address
	ip = ip.To16()
	if ip == nil {
		return fmt.Errorf("not an IPv6 address: %s", ipStr)
	}

	// Check if the IP is within our CIDR
	if m.cidr == nil {
		m.existingIPs[ip.String()] = true
		return nil
	}

	if !m.cidr.Contains(ip) {
		return fmt.Errorf("IPv6 address %s is not within the CIDR %s", ipStr, m.cidr.String())
	}

	m.existingIPs[ip.String()] = true
	return nil
}

// GenerateRandomIPv6 generates a random IPv6 address within the CIDR
func (m *IPv6Manager) GenerateRandomIPv6() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cidr == nil {
		return "", fmt.Errorf("CIDR not set")
	}

	// Get prefix length
	prefixLen, _ := m.cidr.Mask.Size()
	hostBits := min(128-prefixLen, 63)

	// Calculate maximum possible hosts, capping at 2^63 to avoid overflow
	maxPossible := uint64(1) << hostBits

	// If we've used all possible addresses, return an error
	if uint64(len(m.existingIPs)) >= maxPossible {
		return "", fmt.Errorf("all possible IPv6 addresses in the CIDR have been used")
	}

	// We don't perform exhaustion check upfront, instead we'll try random generation first
	// and then fall back to systematic filling if random generation fails

	// Phase 1: Try random generation up to 100 times
	maxAttempts := 100
	attempts := 0

	for attempts < maxAttempts {
		attempts++

		// Start with the network prefix
		newIP := make(net.IP, net.IPv6len)
		copy(newIP, m.cidr.IP)

		// Generate random bits for the host part
		hostBytes := make([]byte, 16)
		_, err := rand.Read(hostBytes)
		if err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %v", err)
		}

		// Apply network mask to ensure we stay within CIDR
		for i := 0; i < 16; i++ {
			// Apply mask byte-by-byte
			newIP[i] = (newIP[i] & m.cidr.Mask[i]) | (hostBytes[i] & ^m.cidr.Mask[i])
		}

		// Convert to string and check if it's unique
		ipStr := newIP.String()
		if !m.existingIPs[ipStr] {
			// Found a unique address
			m.existingIPs[ipStr] = true
			return ipStr, nil
		}
	}

	// Phase 2: If random generation failed, systematically look for gaps

	// Otherwise try to find a gap systematically
	// This is a simplified approach that works for small subnets
	// For larger subnets, this would be extremely inefficient
	ip := make(net.IP, net.IPv6len)
	copy(ip, m.cidr.IP)

	// Try up to another maxAttempts different IPs
	for i := 0; i < maxAttempts; i++ {
		// Increment the last byte first, then ripple carry
		for j := 15; j >= 0; j-- {
			ip[j]++
			if ip[j] != 0 {
				break // No carry needed
			}
		}

		// Give up if went outside our subnet
		if !m.cidr.Contains(ip) {
			break
		}

		ipStr := ip.String()
		if !m.existingIPs[ipStr] {
			m.existingIPs[ipStr] = true
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("failed to generate a unique IPv6 address after %d attempts", maxAttempts*2)
}

// GetExistingIPs returns all existing IPs managed by this instance
func (m *IPv6Manager) GetExistingIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ips := make([]string, 0, len(m.existingIPs))
	for ip := range m.existingIPs {
		ips = append(ips, ip)
	}

	return ips
}

// WithdrawIP removes an IPv6 address from the manager
// If the IP doesn't exist, the operation succeeds silently
func (m *IPv6Manager) WithdrawIP(ipStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Invalid IP format, just return silently
		return
	}

	// Ensure it's an IPv6 address
	ip = ip.To16()
	if ip == nil {
		// Not an IPv6 address, just return silently
		return
	}

	// Remove the IP from the tracking map
	delete(m.existingIPs, ip.String())
}

// Function to compute subnet based on a variable
func ComputeMetalnetSubnet(baseIP string, secondaryPool bool) string {
	// Parse the base IPv6 address
	ip := net.ParseIP(baseIP)
	if ip == nil || ip.To16() == nil {
		return ""
	}

	// The first 64 bits (8 bytes) is the host address: 2001:db8:abcd:abcd::
	result := make(net.IP, len(ip))
	copy(result, ip)

	// Next 16 bits indicate the address type on that host
	//  0000..7fff - host only
	//  d000..dfff - dpservice
	//  ffff - podIPs
	result[8] = 0xd0
	result[9] = 0x00

	// Next 8 bits hold dpservice address flags
	//   #define DP_UNDERLAY_FLAG_EXTERNALLY_GENERATED 0x80
	//   #define DP_UNDERLAY_FLAG_SECONDARY_POOL 0x40
	if secondaryPool {
		result[10] = byte(0x80 | 0x40)
	} else {
		result[10] = byte(0x80)
	}

	// That's 88 bits in total as a network address
	subnetMask := 88
	for i := 11; i < 16; i++ {
		result[i] = 0
	}

	// Format the result using Go's IPv6 formatting (which includes proper compression)
	// and append the subnet mask
	return fmt.Sprintf("%s/%d", result.String(), subnetMask)
}
