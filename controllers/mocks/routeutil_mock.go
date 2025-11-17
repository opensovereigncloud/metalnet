package mocks

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/ironcore-dev/metalbond/pb"
	"github.com/ironcore-dev/metalnet/metalbond"
)

// RouteUtilMock is a manual mock implementation of metalbond.RouteUtil
type RouteUtilMock struct {
	mu sync.RWMutex

	// Call tracking
	announceRouteCalls    int
	withdrawRouteCalls    int
	subscribeCalls        int
	unsubscribeCalls      int
	isSubscribedCalls     int
	getRoutesForVniCalls  int
	isRouteAnnouncedCalls int

	// State tracking
	announcedRoutes    []RouteInfo
	subscribedVNIs     map[metalbond.VNI]bool
	routeAnnouncements map[string]bool // key: vni-prefix-targetAddr

	// Configurable responses
	announceRouteError   error
	withdrawRouteError   error
	subscribeError       error
	unsubscribeError     error
	getRoutesForVniError error
}

// RouteInfo tracks route announcement details
type RouteInfo struct {
	VNI         metalbond.VNI
	Destination metalbond.Destination
	NextHop     metalbond.NextHop
}

// NewRouteUtilMock creates a new mock RouteUtil
func NewRouteUtilMock() *RouteUtilMock {
	return &RouteUtilMock{
		subscribedVNIs:     make(map[metalbond.VNI]bool),
		routeAnnouncements: make(map[string]bool),
	}
}

// Reset clears all state and call counts
func (m *RouteUtilMock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.announceRouteCalls = 0
	m.withdrawRouteCalls = 0
	m.subscribeCalls = 0
	m.unsubscribeCalls = 0
	m.isSubscribedCalls = 0
	m.getRoutesForVniCalls = 0
	m.isRouteAnnouncedCalls = 0

	m.announcedRoutes = nil
	m.subscribedVNIs = make(map[metalbond.VNI]bool)
	m.routeAnnouncements = make(map[string]bool)

	m.announceRouteError = nil
	m.withdrawRouteError = nil
	m.subscribeError = nil
	m.unsubscribeError = nil
	m.getRoutesForVniError = nil
}

// AnnounceRoute announces a route via BGP
func (m *RouteUtilMock) AnnounceRoute(ctx context.Context, vni metalbond.VNI, destination metalbond.Destination, nextHop metalbond.NextHop) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.announceRouteCalls++

	if m.announceRouteError != nil {
		return m.announceRouteError
	}

	routeInfo := RouteInfo{
		VNI:         vni,
		Destination: destination,
		NextHop:     nextHop,
	}
	m.announcedRoutes = append(m.announcedRoutes, routeInfo)

	// Track in routeAnnouncements map for IsRouteAnnounced queries
	key := makeRouteKey(vni, destination.Prefix, nextHop.TargetAddress, nextHop.TargetHopType, nextHop.TargetNATMinPort, nextHop.TargetNATMaxPort)
	m.routeAnnouncements[key] = true

	return nil
}

// WithdrawRoute withdraws a route from BGP
func (m *RouteUtilMock) WithdrawRoute(ctx context.Context, vni metalbond.VNI, destination metalbond.Destination, nextHop metalbond.NextHop) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.withdrawRouteCalls++

	if m.withdrawRouteError != nil {
		return m.withdrawRouteError
	}

	// Remove from routeAnnouncements map
	key := makeRouteKey(vni, destination.Prefix, nextHop.TargetAddress, nextHop.TargetHopType, nextHop.TargetNATMinPort, nextHop.TargetNATMaxPort)
	delete(m.routeAnnouncements, key)

	return nil
}

// Subscribe subscribes to a VNI
func (m *RouteUtilMock) Subscribe(ctx context.Context, vni metalbond.VNI) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribeCalls++

	if m.subscribeError != nil {
		return m.subscribeError
	}

	m.subscribedVNIs[vni] = true
	return nil
}

// Unsubscribe unsubscribes from a VNI
func (m *RouteUtilMock) Unsubscribe(ctx context.Context, vni metalbond.VNI) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsubscribeCalls++

	if m.unsubscribeError != nil {
		return m.unsubscribeError
	}

	delete(m.subscribedVNIs, vni)
	return nil
}

// IsSubscribed checks if subscribed to a VNI
func (m *RouteUtilMock) IsSubscribed(ctx context.Context, vni metalbond.VNI) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.isSubscribedCalls++

	return m.subscribedVNIs[vni]
}

// GetRoutesForVni retrieves routes for a VNI
func (m *RouteUtilMock) GetRoutesForVni(ctx context.Context, vni metalbond.VNI) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getRoutesForVniCalls++

	if m.getRoutesForVniError != nil {
		return m.getRoutesForVniError
	}

	return nil
}

// IsRouteAnnounced checks if a specific route is announced
func (m *RouteUtilMock) IsRouteAnnounced(ctx context.Context, vni metalbond.VNI, dest metalbond.Destination, targetAddress netip.Addr, targetType pb.NextHopType, natPortFrom, natPortTo uint16) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.isRouteAnnouncedCalls++

	key := makeRouteKey(vni, dest.Prefix, targetAddress, targetType, natPortFrom, natPortTo)
	return m.routeAnnouncements[key]
}

// =============================================================================
// Helper Methods for Test Configuration
// =============================================================================

// SetAnnounceRouteError sets an error for AnnounceRoute calls
func (m *RouteUtilMock) SetAnnounceRouteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.announceRouteError = err
}

// SetWithdrawRouteError sets an error for WithdrawRoute calls
func (m *RouteUtilMock) SetWithdrawRouteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.withdrawRouteError = err
}

// SetSubscribeError sets an error for Subscribe calls
func (m *RouteUtilMock) SetSubscribeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribeError = err
}

// SetUnsubscribeError sets an error for Unsubscribe calls
func (m *RouteUtilMock) SetUnsubscribeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsubscribeError = err
}

// PreAnnounceRoute pre-populates an announced route (for testing scenarios where route already exists)
func (m *RouteUtilMock) PreAnnounceRoute(vni metalbond.VNI, prefix netip.Prefix, targetAddr netip.Addr, hopType pb.NextHopType, minPort, maxPort uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeRouteKey(vni, prefix, targetAddr, hopType, minPort, maxPort)
	m.routeAnnouncements[key] = true
}

// =============================================================================
// Call Count Getters (for test assertions)
// =============================================================================

func (m *RouteUtilMock) AnnounceRouteCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.announceRouteCalls
}

func (m *RouteUtilMock) WithdrawRouteCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.withdrawRouteCalls
}

func (m *RouteUtilMock) SubscribeCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.subscribeCalls
}

func (m *RouteUtilMock) UnsubscribeCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.unsubscribeCalls
}

func (m *RouteUtilMock) IsSubscribedCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isSubscribedCalls
}

func (m *RouteUtilMock) GetRoutesForVniCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getRoutesForVniCalls
}

func (m *RouteUtilMock) IsRouteAnnouncedCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isRouteAnnouncedCalls
}

// =============================================================================
// State Getters (for test assertions)
// =============================================================================

func (m *RouteUtilMock) GetAnnouncedRoutes() []RouteInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return copy to avoid race conditions
	routes := make([]RouteInfo, len(m.announcedRoutes))
	copy(routes, m.announcedRoutes)
	return routes
}

func (m *RouteUtilMock) GetSubscribedVNIs() []metalbond.VNI {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vnis := make([]metalbond.VNI, 0, len(m.subscribedVNIs))
	for vni := range m.subscribedVNIs {
		vnis = append(vnis, vni)
	}
	return vnis
}

// =============================================================================
// Private Helpers
// =============================================================================

func makeRouteKey(vni metalbond.VNI, prefix netip.Prefix, targetAddr netip.Addr, hopType pb.NextHopType, minPort, maxPort uint16) string {
	return fmt.Sprintf("%d-%s-%s-%d-%d-%d", vni, prefix.String(), targetAddr.String(), hopType, minPort, maxPort)
}
