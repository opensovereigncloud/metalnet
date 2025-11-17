package mocks

import (
	"fmt"
	"sync"

	"github.com/jaypipes/ghw"
	"k8s.io/apimachinery/pkg/types"
)

// NetFnsManagerMock is a manual mock implementation of netfns.Manager
type NetFnsManagerMock struct {
	mu sync.RWMutex

	// Call tracking
	getOrClaimCalls int
	releaseCalls    int
	releaseAllCalls int

	// Stored call arguments
	getOrClaimArgs []types.UID
	releaseArgs    []types.UID

	// State tracking
	claims map[types.UID]*ghw.PCIAddress

	// Configurable responses
	getOrClaimResponse *ghw.PCIAddress
	getOrClaimError    error
	releaseError       error
	releaseAllError    error

	// Available addresses for allocation
	availableAddresses []*ghw.PCIAddress
	nextAddressIndex   int
}

// NewNetFnsManagerMock creates a new mock NetFns Manager
func NewNetFnsManagerMock() *NetFnsManagerMock {
	// Create some default PCI addresses for allocation
	defaultAddresses := []*ghw.PCIAddress{
		{Domain: "0000", Bus: "01", Device: "00", Function: "0"},
		{Domain: "0000", Bus: "01", Device: "00", Function: "1"},
		{Domain: "0000", Bus: "01", Device: "00", Function: "2"},
		{Domain: "0000", Bus: "01", Device: "00", Function: "3"},
		{Domain: "0000", Bus: "02", Device: "00", Function: "0"},
	}

	return &NetFnsManagerMock{
		claims:             make(map[types.UID]*ghw.PCIAddress),
		availableAddresses: defaultAddresses,
		nextAddressIndex:   0,
	}
}

// Reset clears all state and call counts
func (m *NetFnsManagerMock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getOrClaimCalls = 0
	m.releaseCalls = 0
	m.releaseAllCalls = 0

	m.getOrClaimArgs = nil
	m.releaseArgs = nil

	m.claims = make(map[types.UID]*ghw.PCIAddress)

	m.getOrClaimResponse = nil
	m.getOrClaimError = nil
	m.releaseError = nil
	m.releaseAllError = nil

	m.nextAddressIndex = 0
}

// Get gets an existing PCI address claim for a UID
func (m *NetFnsManagerMock) Get(uid types.UID) (*ghw.PCIAddress, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	addr, exists := m.claims[uid]
	if !exists {
		return nil, fmt.Errorf("no PCI address claimed for UID %s", uid)
	}
	return addr, nil
}

// GetOrClaim gets or claims a PCI address for a UID
func (m *NetFnsManagerMock) GetOrClaim(uid types.UID) (*ghw.PCIAddress, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getOrClaimCalls++
	m.getOrClaimArgs = append(m.getOrClaimArgs, uid)

	if m.getOrClaimError != nil {
		return nil, m.getOrClaimError
	}

	// If custom response is set, use it
	if m.getOrClaimResponse != nil {
		m.claims[uid] = m.getOrClaimResponse
		return m.getOrClaimResponse, nil
	}

	// Check if already claimed
	if addr, exists := m.claims[uid]; exists {
		return addr, nil
	}

	// Allocate new address
	if m.nextAddressIndex >= len(m.availableAddresses) {
		return nil, fmt.Errorf("no more PCI addresses available for allocation")
	}

	addr := m.availableAddresses[m.nextAddressIndex]
	m.nextAddressIndex++
	m.claims[uid] = addr

	return addr, nil
}

// Release releases a claimed PCI address
func (m *NetFnsManagerMock) Release(uid types.UID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseCalls++
	m.releaseArgs = append(m.releaseArgs, uid)

	if m.releaseError != nil {
		return m.releaseError
	}

	delete(m.claims, uid)
	return nil
}

// ReleaseAll releases all claimed PCI addresses
func (m *NetFnsManagerMock) ReleaseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseAllCalls++

	if m.releaseAllError != nil {
		return m.releaseAllError
	}

	m.claims = make(map[types.UID]*ghw.PCIAddress)
	m.nextAddressIndex = 0
	return nil
}

// =============================================================================
// Helper Methods for Test Configuration
// =============================================================================

// SetGetOrClaimResponse sets a specific response for GetOrClaim calls
func (m *NetFnsManagerMock) SetGetOrClaimResponse(addr *ghw.PCIAddress, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getOrClaimResponse = addr
	m.getOrClaimError = err
}

// SetGetOrClaimError sets an error for GetOrClaim calls (for testing allocation failures)
func (m *NetFnsManagerMock) SetGetOrClaimError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getOrClaimError = err
}

// SetReleaseError sets an error for Release calls
func (m *NetFnsManagerMock) SetReleaseError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseError = err
}

// SetAvailableAddresses sets custom available addresses for allocation
func (m *NetFnsManagerMock) SetAvailableAddresses(addresses []*ghw.PCIAddress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.availableAddresses = addresses
	m.nextAddressIndex = 0
}

// PreClaim pre-allocates a PCI address to a UID (for testing existing claims)
func (m *NetFnsManagerMock) PreClaim(uid types.UID, addr *ghw.PCIAddress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claims[uid] = addr
}

// =============================================================================
// Call Count Getters (for test assertions)
// =============================================================================

func (m *NetFnsManagerMock) GetOrClaimCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getOrClaimCalls
}

func (m *NetFnsManagerMock) ReleaseCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.releaseCalls
}

func (m *NetFnsManagerMock) ReleaseAllCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.releaseAllCalls
}

// =============================================================================
// Call Arguments Getters (for detailed assertions)
// =============================================================================

func (m *NetFnsManagerMock) GetGetOrClaimArgs() []types.UID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return copy to avoid race conditions
	args := make([]types.UID, len(m.getOrClaimArgs))
	copy(args, m.getOrClaimArgs)
	return args
}

func (m *NetFnsManagerMock) GetReleaseArgs() []types.UID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return copy to avoid race conditions
	args := make([]types.UID, len(m.releaseArgs))
	copy(args, m.releaseArgs)
	return args
}

// =============================================================================
// State Getters (for test assertions)
// =============================================================================

func (m *NetFnsManagerMock) GetClaims() map[types.UID]*ghw.PCIAddress {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return copy to avoid race conditions
	claims := make(map[types.UID]*ghw.PCIAddress)
	for k, v := range m.claims {
		claims[k] = v
	}
	return claims
}

func (m *NetFnsManagerMock) GetClaimedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.claims)
}

func (m *NetFnsManagerMock) IsClaimedBy(uid types.UID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.claims[uid]
	return exists
}

func (m *NetFnsManagerMock) GetClaimedAddress(uid types.UID) (*ghw.PCIAddress, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	addr, exists := m.claims[uid]
	return addr, exists
}
