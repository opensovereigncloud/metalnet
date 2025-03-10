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

	// Ensure it's an IPv6 address
	ip = ip.To16()
	if ip == nil {
		return fmt.Errorf("not an IPv6 address: %s", ipStr)
	}

	// Only add if it's within our CIDR (silently skip if not)
	if m.cidr == nil || m.cidr.Contains(ip) {
		m.existingIPs[ip.String()] = true
	}

	return nil
}

// GenerateRandomIPv6 generates a random IPv6 address within the CIDR
func (m *IPv6Manager) GenerateRandomIPv6() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cidr == nil {
		return "", fmt.Errorf("CIDR not set")
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
	// Count addresses in the CIDR
	addressesInCidr := 0
	for ip := range m.existingIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil && m.cidr.Contains(parsedIP) {
			addressesInCidr++
		}
	}

	// Get prefix length
	prefixLen, _ := m.cidr.Mask.Size()
	hostBits := 128 - prefixLen

	// Calculate maximum possible hosts, capping at 2^63 to avoid overflow
	maxPossible := int64(1)
	if hostBits < 63 {
		maxPossible = int64(1) << uint(hostBits)
	}

	// If we've used all possible addresses, return an error
	if int64(addressesInCidr) >= maxPossible {
		return "", fmt.Errorf("all possible IPv6 addresses in the CIDR have been used")
	}

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

		// Skip if not in our subnet
		if !m.cidr.Contains(ip) {
			continue
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

// Function to compute /66 subnet based on a variable
func ComputeIPv6Subnet66(baseIP string, subnetIndex int) string {
	// Parse the base IPv6 address
	ip := net.ParseIP(baseIP)
	if ip == nil || ip.To16() == nil {
		return ""
	}

	// The subnet index should be 0-3 since we have 2 bits (4 possible values)
	if subnetIndex < 0 || subnetIndex > 3 {
		return ""
	}

	// Calculate the 5th segment of the IPv6 address
	// For a /66 subnet:
	// Index 0 -> 0000:: (/66)
	// Index 1 -> 4000:: (/66)  (01 in the first two bits)
	// Index 2 -> 8000:: (/66)  (10 in the first two bits)
	// Index 3 -> c000:: (/66)  (11 in the first two bits)
	fifthSegment := subnetIndex << 14 // Shift left by 14 bits (16-2)

	// Copy the original IP and modify the 5th segment
	result := make(net.IP, len(ip))
	copy(result, ip)

	// Set the 5th segment (bytes 8-9 in the IPv6 address)
	result[8] = byte(fifthSegment >> 8)
	result[9] = byte(fifthSegment)

	return fmt.Sprintf("%s/66", result.String())
}
