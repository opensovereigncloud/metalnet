package mocks

import (
	"context"
	"net/netip"
	"sync"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
)

// DPDKClientMock is a manual mock implementation of dpdk.Client
// It tracks all method calls and allows configuring responses for testing
type DPDKClientMock struct {
	mu sync.RWMutex

	// Stateful tracking of created resources
	createdInterfaces   map[string]*dpdk.Interface   // key: InterfaceId
	createdVirtualIPs   map[string]*dpdk.VirtualIP   // key: InterfaceId
	createdNATs         map[string]*dpdk.Nat         // key: InterfaceId
	createdLoadBalancers map[string]*dpdk.LoadBalancer // key: LoadBalancerId

	// Call tracking
	getInterfaceCalls             int
	createInterfaceCalls          int
	deleteInterfaceCalls          int
	listPrefixesCalls             int
	createPrefixCalls             int
	deletePrefixCalls             int
	listLoadBalancerPrefixesCalls int
	createLoadBalancerPrefixCalls int
	deleteLoadBalancerPrefixCalls int
	getNatCalls                   int
	createNatCalls                int
	deleteNatCalls                int
	listNeighborNatsCalls         int
	deleteNeighborNatCalls        int
	getVirtualIPCalls             int
	createVirtualIPCalls          int
	deleteVirtualIPCalls          int
	listRoutesCalls               int
	createRouteCalls              int
	deleteRouteCalls              int
	getVniCalls                   int
	getLoadBalancerCalls          int
	createLoadBalancerCalls       int
	deleteLoadBalancerCalls       int

	// Stored call arguments (for assertions)
	getInterfaceArgs             []string
	createInterfaceArgs          []*dpdk.Interface
	createPrefixArgs             []*dpdk.Prefix
	deletePrefixArgs             []netip.Prefix
	createLoadBalancerPrefixArgs []*dpdk.LoadBalancerPrefix
	createNatArgs                []*dpdk.Nat
	createVirtualIPArgs          []*dpdk.VirtualIP
	createLoadBalancerArgs       []*dpdk.LoadBalancer

	// Configurable responses
	getInterfaceResponse             *dpdk.Interface
	getInterfaceError                error
	createInterfaceResponse          *dpdk.Interface
	createInterfaceError             error
	deleteInterfaceResponse          *dpdk.Interface
	deleteInterfaceError             error
	listPrefixesResponse             *dpdk.PrefixList
	listPrefixesError                error
	createPrefixResponse             *dpdk.Prefix
	createPrefixError                error
	deletePrefixResponse             *dpdk.Prefix
	deletePrefixError                error
	listLoadBalancerPrefixesResponse *dpdk.PrefixList
	listLoadBalancerPrefixesError    error
	createLoadBalancerPrefixResponse *dpdk.LoadBalancerPrefix
	createLoadBalancerPrefixError    error
	deleteLoadBalancerPrefixResponse *dpdk.LoadBalancerPrefix
	deleteLoadBalancerPrefixError    error
	getNatResponse                   *dpdk.Nat
	getNatError                      error
	createNatResponse                *dpdk.Nat
	createNatError                   error
	deleteNatResponse                *dpdk.Nat
	deleteNatError                   error
	listNeighborNatsResponse         *dpdk.NatList
	listNeighborNatsError            error
	deleteNeighborNatResponse        *dpdk.NeighborNat
	deleteNeighborNatError           error
	getVirtualIPResponse             *dpdk.VirtualIP
	getVirtualIPError                error
	createVirtualIPResponse          *dpdk.VirtualIP
	createVirtualIPError             error
	deleteVirtualIPResponse          *dpdk.VirtualIP
	deleteVirtualIPError             error
	listRoutesResponse               *dpdk.RouteList
	listRoutesError                  error
	createRouteResponse              *dpdk.Route
	createRouteError                 error
	deleteRouteResponse              *dpdk.Route
	deleteRouteError                 error
	listFirewallRulesResponse        *dpdk.FirewallRuleList
	listFirewallRulesError           error
	deleteFirewallRuleError          error
	getVniResponse                   *dpdk.Vni
	getVniError                      error
	getLoadBalancerResponse          *dpdk.LoadBalancer
	getLoadBalancerError             error
	createLoadBalancerResponse       *dpdk.LoadBalancer
	createLoadBalancerError          error
	deleteLoadBalancerResponse       *dpdk.LoadBalancer
	deleteLoadBalancerError          error
}

// NewDPDKClientMock creates a new mock DPDK client
func NewDPDKClientMock() *DPDKClientMock {
	return &DPDKClientMock{
		// Initialize stateful tracking
		createdInterfaces:    make(map[string]*dpdk.Interface),
		createdVirtualIPs:    make(map[string]*dpdk.VirtualIP),
		createdNATs:          make(map[string]*dpdk.Nat),
		createdLoadBalancers: make(map[string]*dpdk.LoadBalancer),

		// Initialize with empty responses
		listPrefixesResponse:             &dpdk.PrefixList{Items: []dpdk.Prefix{}},
		listLoadBalancerPrefixesResponse: &dpdk.PrefixList{Items: []dpdk.Prefix{}},
		listNeighborNatsResponse:         &dpdk.NatList{Items: []dpdk.Nat{}},
		listRoutesResponse:               &dpdk.RouteList{Items: []dpdk.Route{}},
	}
}

// Reset clears all call counts and configured responses
func (m *DPDKClientMock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear stateful tracking
	m.createdInterfaces = make(map[string]*dpdk.Interface)
	m.createdVirtualIPs = make(map[string]*dpdk.VirtualIP)
	m.createdNATs = make(map[string]*dpdk.Nat)
	m.createdLoadBalancers = make(map[string]*dpdk.LoadBalancer)

	m.getInterfaceCalls = 0
	m.createInterfaceCalls = 0
	m.deleteInterfaceCalls = 0
	m.listPrefixesCalls = 0
	m.createPrefixCalls = 0
	m.deletePrefixCalls = 0
	m.listLoadBalancerPrefixesCalls = 0
	m.createLoadBalancerPrefixCalls = 0
	m.deleteLoadBalancerPrefixCalls = 0
	m.getNatCalls = 0
	m.createNatCalls = 0
	m.deleteNatCalls = 0
	m.listNeighborNatsCalls = 0
	m.deleteNeighborNatCalls = 0
	m.getVirtualIPCalls = 0
	m.createVirtualIPCalls = 0
	m.deleteVirtualIPCalls = 0
	m.listRoutesCalls = 0
	m.createRouteCalls = 0
	m.deleteRouteCalls = 0
	m.getVniCalls = 0
	m.getLoadBalancerCalls = 0
	m.createLoadBalancerCalls = 0
	m.deleteLoadBalancerCalls = 0

	m.getInterfaceArgs = nil
	m.createInterfaceArgs = nil
	m.createPrefixArgs = nil
	m.deletePrefixArgs = nil
	m.createLoadBalancerPrefixArgs = nil
	m.createNatArgs = nil
	m.createVirtualIPArgs = nil
	m.createLoadBalancerArgs = nil

	m.getInterfaceResponse = nil
	m.getInterfaceError = nil
	m.createInterfaceResponse = nil
	m.createInterfaceError = nil
	m.listPrefixesResponse = &dpdk.PrefixList{Items: []dpdk.Prefix{}}
	m.listPrefixesError = nil
	m.listLoadBalancerPrefixesResponse = &dpdk.PrefixList{Items: []dpdk.Prefix{}}
	m.listLoadBalancerPrefixesError = nil
	m.listNeighborNatsResponse = &dpdk.NatList{Items: []dpdk.Nat{}}
	m.listNeighborNatsError = nil
	m.listRoutesResponse = &dpdk.RouteList{Items: []dpdk.Route{}}
	m.listRoutesError = nil
	m.getVniResponse = nil
	m.getVniError = nil
	m.getLoadBalancerResponse = nil
	m.getLoadBalancerError = nil
	m.createLoadBalancerResponse = nil
	m.createLoadBalancerError = nil
	m.deleteLoadBalancerResponse = nil
	m.deleteLoadBalancerError = nil
}

// =============================================================================
// Interface Operations
// =============================================================================

func (m *DPDKClientMock) GetInterface(ctx context.Context, id string, ignoredErrors ...[]uint32) (*dpdk.Interface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getInterfaceCalls++
	m.getInterfaceArgs = append(m.getInterfaceArgs, id)

	// Check stateful tracking first
	if iface, exists := m.createdInterfaces[id]; exists {
		return iface, nil
	}

	// Then check configured error response
	if m.getInterfaceError != nil {
		return nil, m.getInterfaceError
	}
	// Then check configured response
	if m.getInterfaceResponse != nil {
		return m.getInterfaceResponse, nil
	}
	// Return NOT_FOUND by default
	return nil, dpdkerrors.NewStatusError(dpdkerrors.NOT_FOUND, "interface not found")
}

func (m *DPDKClientMock) CreateInterface(ctx context.Context, iface *dpdk.Interface, ignoredErrors ...[]uint32) (*dpdk.Interface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createInterfaceCalls++
	m.createInterfaceArgs = append(m.createInterfaceArgs, iface)

	if m.createInterfaceError != nil {
		return nil, m.createInterfaceError
	}
	if m.createInterfaceResponse != nil {
		return m.createInterfaceResponse, nil
	}

	// Store in stateful tracking
	m.createdInterfaces[iface.InterfaceMeta.ID] = iface
	return iface, nil
}

func (m *DPDKClientMock) DeleteInterface(ctx context.Context, id string, ignoredErrors ...[]uint32) (*dpdk.Interface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteInterfaceCalls++

	// Remove from stateful tracking
	delete(m.createdInterfaces, id)

	if m.deleteInterfaceError != nil {
		return nil, m.deleteInterfaceError
	}
	return m.deleteInterfaceResponse, nil
}

func (m *DPDKClientMock) ListInterfaces(ctx context.Context, ignoredErrors ...[]uint32) (*dpdk.InterfaceList, error) {
	return &dpdk.InterfaceList{}, nil
}

// RemoveCreatedInterface removes an interface from stateful tracking (for testing)
func (m *DPDKClientMock) RemoveCreatedInterface(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.createdInterfaces, id)
}

// =============================================================================
// Prefix Operations
// =============================================================================

func (m *DPDKClientMock) ListPrefixes(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.PrefixList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listPrefixesCalls++

	if m.listPrefixesError != nil {
		return nil, m.listPrefixesError
	}
	return m.listPrefixesResponse, nil
}

func (m *DPDKClientMock) CreatePrefix(ctx context.Context, prefix *dpdk.Prefix, ignoredErrors ...[]uint32) (*dpdk.Prefix, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createPrefixCalls++
	m.createPrefixArgs = append(m.createPrefixArgs, prefix)

	if m.createPrefixError != nil {
		return nil, m.createPrefixError
	}
	if m.createPrefixResponse != nil {
		return m.createPrefixResponse, nil
	}
	return prefix, nil
}

func (m *DPDKClientMock) DeletePrefix(ctx context.Context, interfaceID string, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*dpdk.Prefix, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletePrefixCalls++
	if prefix != nil {
		m.deletePrefixArgs = append(m.deletePrefixArgs, *prefix)
	}

	if m.deletePrefixError != nil {
		return nil, m.deletePrefixError
	}
	return m.deletePrefixResponse, nil
}

// =============================================================================
// LoadBalancer Prefix Operations
// =============================================================================

func (m *DPDKClientMock) ListLoadBalancerPrefixes(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.PrefixList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listLoadBalancerPrefixesCalls++

	if m.listLoadBalancerPrefixesError != nil {
		return nil, m.listLoadBalancerPrefixesError
	}
	return m.listLoadBalancerPrefixesResponse, nil
}

func (m *DPDKClientMock) CreateLoadBalancerPrefix(ctx context.Context, prefix *dpdk.LoadBalancerPrefix, ignoredErrors ...[]uint32) (*dpdk.LoadBalancerPrefix, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createLoadBalancerPrefixCalls++
	m.createLoadBalancerPrefixArgs = append(m.createLoadBalancerPrefixArgs, prefix)

	if m.createLoadBalancerPrefixError != nil {
		return nil, m.createLoadBalancerPrefixError
	}
	if m.createLoadBalancerPrefixResponse != nil {
		return m.createLoadBalancerPrefixResponse, nil
	}
	return prefix, nil
}

func (m *DPDKClientMock) DeleteLoadBalancerPrefix(ctx context.Context, interfaceID string, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*dpdk.LoadBalancerPrefix, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLoadBalancerPrefixCalls++

	if m.deleteLoadBalancerPrefixError != nil {
		return nil, m.deleteLoadBalancerPrefixError
	}
	return m.deleteLoadBalancerPrefixResponse, nil
}

// =============================================================================
// NAT Operations
// =============================================================================

func (m *DPDKClientMock) GetNat(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.Nat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getNatCalls++

	if m.getNatError != nil {
		return nil, m.getNatError
	}
	if m.getNatResponse != nil {
		return m.getNatResponse, nil
	}
	// Check stateful tracking
	if nat, exists := m.createdNATs[interfaceID]; exists {
		return nat, nil
	}
	// NAT doesn't exist - return NO_VM error (controller treats this as "doesn't exist, ok")
	return nil, dpdkerrors.NewStatusError(dpdkerrors.NO_VM, "nat not found")
}

func (m *DPDKClientMock) CreateNat(ctx context.Context, nat *dpdk.Nat, ignoredErrors ...[]uint32) (*dpdk.Nat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createNatCalls++
	m.createNatArgs = append(m.createNatArgs, nat)

	if m.createNatError != nil {
		return nil, m.createNatError
	}
	if m.createNatResponse != nil {
		return m.createNatResponse, nil
	}

	// Store in stateful tracking
	m.createdNATs[nat.NatMeta.InterfaceID] = nat
	return nat, nil
}

func (m *DPDKClientMock) DeleteNat(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.Nat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteNatCalls++

	// Remove from stateful tracking
	delete(m.createdNATs, interfaceID)

	if m.deleteNatError != nil {
		return nil, m.deleteNatError
	}
	return m.deleteNatResponse, nil
}

func (m *DPDKClientMock) ListNeighborNats(ctx context.Context, natIP *netip.Addr, ignoredErrors ...[]uint32) (*dpdk.NatList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listNeighborNatsCalls++

	if m.listNeighborNatsError != nil {
		return nil, m.listNeighborNatsError
	}
	return m.listNeighborNatsResponse, nil
}

func (m *DPDKClientMock) DeleteNeighborNat(ctx context.Context, neighborNat *dpdk.NeighborNat, ignoredErrors ...[]uint32) (*dpdk.NeighborNat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteNeighborNatCalls++

	if m.deleteNeighborNatError != nil {
		return nil, m.deleteNeighborNatError
	}
	return m.deleteNeighborNatResponse, nil
}

func (m *DPDKClientMock) ListLocalNats(ctx context.Context, natIP *netip.Addr, ignoredErrors ...[]uint32) (*dpdk.NatList, error) {
	return &dpdk.NatList{}, nil
}

func (m *DPDKClientMock) CreateNeighborNat(ctx context.Context, nat *dpdk.NeighborNat, ignoredErrors ...[]uint32) (*dpdk.NeighborNat, error) {
	return nat, nil
}

func (m *DPDKClientMock) ListNats(ctx context.Context, natIP *netip.Addr, natType string, ignoredErrors ...[]uint32) (*dpdk.NatList, error) {
	return &dpdk.NatList{}, nil
}

// =============================================================================
// VirtualIP Operations
// =============================================================================

func (m *DPDKClientMock) GetVirtualIP(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.VirtualIP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getVirtualIPCalls++

	if m.getVirtualIPError != nil {
		return nil, m.getVirtualIPError
	}
	if m.getVirtualIPResponse != nil {
		return m.getVirtualIPResponse, nil
	}
	// Check stateful tracking
	if vip, exists := m.createdVirtualIPs[interfaceID]; exists {
		return vip, nil
	}
	// VirtualIP doesn't exist - return NO_VM error (controller treats this as "doesn't exist, ok")
	return nil, dpdkerrors.NewStatusError(dpdkerrors.NO_VM, "virtualip not found")
}

func (m *DPDKClientMock) CreateVirtualIP(ctx context.Context, virtualIP *dpdk.VirtualIP, ignoredErrors ...[]uint32) (*dpdk.VirtualIP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createVirtualIPCalls++
	m.createVirtualIPArgs = append(m.createVirtualIPArgs, virtualIP)

	if m.createVirtualIPError != nil {
		return nil, m.createVirtualIPError
	}
	if m.createVirtualIPResponse != nil {
		return m.createVirtualIPResponse, nil
	}

	// Store in stateful tracking
	m.createdVirtualIPs[virtualIP.VirtualIPMeta.InterfaceID] = virtualIP
	return virtualIP, nil
}

func (m *DPDKClientMock) DeleteVirtualIP(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.VirtualIP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteVirtualIPCalls++

	// Remove from stateful tracking
	delete(m.createdVirtualIPs, interfaceID)

	if m.deleteVirtualIPError != nil {
		return nil, m.deleteVirtualIPError
	}
	return m.deleteVirtualIPResponse, nil
}

// =============================================================================
// Route Operations
// =============================================================================

func (m *DPDKClientMock) ListRoutes(ctx context.Context, vni uint32, ignoredErrors ...[]uint32) (*dpdk.RouteList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listRoutesCalls++

	if m.listRoutesError != nil {
		return nil, m.listRoutesError
	}
	return m.listRoutesResponse, nil
}

func (m *DPDKClientMock) CreateRoute(ctx context.Context, route *dpdk.Route, ignoredErrors ...[]uint32) (*dpdk.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createRouteCalls++

	if m.createRouteError != nil {
		// Check if this error should be ignored
		if shouldIgnoreError(m.createRouteError, ignoredErrors) {
			// Return the route successfully if the error is ignored
			if m.createRouteResponse != nil {
				return m.createRouteResponse, nil
			}
			return route, nil
		}
		return nil, m.createRouteError
	}
	if m.createRouteResponse != nil {
		return m.createRouteResponse, nil
	}
	return route, nil
}

func (m *DPDKClientMock) DeleteRoute(ctx context.Context, vni uint32, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*dpdk.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteRouteCalls++

	if m.deleteRouteError != nil {
		// Check if this error should be ignored
		if shouldIgnoreError(m.deleteRouteError, ignoredErrors) {
			// Return successfully if the error is ignored
			return m.deleteRouteResponse, nil
		}
		return nil, m.deleteRouteError
	}
	return m.deleteRouteResponse, nil
}

// =============================================================================
// LoadBalancer Operations
// =============================================================================

func (m *DPDKClientMock) GetLoadBalancer(ctx context.Context, id string, ignoredErrors ...[]uint32) (*dpdk.LoadBalancer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getLoadBalancerCalls++

	// Check stateful tracking first
	if lb, exists := m.createdLoadBalancers[id]; exists {
		return lb, nil
	}

	// Then check configured error response
	if m.getLoadBalancerError != nil {
		return nil, m.getLoadBalancerError
	}
	// Then check configured response
	if m.getLoadBalancerResponse != nil {
		return m.getLoadBalancerResponse, nil
	}
	// Return NOT_FOUND by default
	return nil, dpdkerrors.NewStatusError(dpdkerrors.NOT_FOUND, "loadbalancer not found")
}

func (m *DPDKClientMock) ListLoadBalancers(ctx context.Context, ignoredErrors ...[]uint32) (*dpdk.LoadBalancerList, error) {
	return &dpdk.LoadBalancerList{}, nil
}

func (m *DPDKClientMock) CreateLoadBalancer(ctx context.Context, lb *dpdk.LoadBalancer, ignoredErrors ...[]uint32) (*dpdk.LoadBalancer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createLoadBalancerCalls++
	m.createLoadBalancerArgs = append(m.createLoadBalancerArgs, lb)

	if m.createLoadBalancerError != nil {
		return nil, m.createLoadBalancerError
	}
	if m.createLoadBalancerResponse != nil {
		return m.createLoadBalancerResponse, nil
	}

	// Store in stateful tracking
	m.createdLoadBalancers[lb.LoadBalancerMeta.ID] = lb
	return lb, nil
}

func (m *DPDKClientMock) DeleteLoadBalancer(ctx context.Context, id string, ignoredErrors ...[]uint32) (*dpdk.LoadBalancer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLoadBalancerCalls++

	// Remove from stateful tracking
	delete(m.createdLoadBalancers, id)

	if m.deleteLoadBalancerError != nil {
		return nil, m.deleteLoadBalancerError
	}
	return m.deleteLoadBalancerResponse, nil
}

func (m *DPDKClientMock) ListLoadBalancerTargets(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.LoadBalancerTargetList, error) {
	return &dpdk.LoadBalancerTargetList{}, nil
}

func (m *DPDKClientMock) CreateLoadBalancerTarget(ctx context.Context, lbtarget *dpdk.LoadBalancerTarget, ignoredErrors ...[]uint32) (*dpdk.LoadBalancerTarget, error) {
	return lbtarget, nil
}

func (m *DPDKClientMock) DeleteLoadBalancerTarget(ctx context.Context, id string, targetIP *netip.Addr, ignoredErrors ...[]uint32) (*dpdk.LoadBalancerTarget, error) {
	return nil, nil
}

// =============================================================================
// Firewall Operations (commented out in controller but interface exists)
// =============================================================================

func (m *DPDKClientMock) ListFirewallRules(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*dpdk.FirewallRuleList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listFirewallRulesError != nil {
		return nil, m.listFirewallRulesError
	}
	if m.listFirewallRulesResponse != nil {
		return m.listFirewallRulesResponse, nil
	}
	return &dpdk.FirewallRuleList{}, nil
}

func (m *DPDKClientMock) CreateFirewallRule(ctx context.Context, fwRule *dpdk.FirewallRule, ignoredErrors ...[]uint32) (*dpdk.FirewallRule, error) {
	return fwRule, nil
}

func (m *DPDKClientMock) GetFirewallRule(ctx context.Context, interfaceID string, ruleID string, ignoredErrors ...[]uint32) (*dpdk.FirewallRule, error) {
	return nil, nil
}

func (m *DPDKClientMock) DeleteFirewallRule(ctx context.Context, interfaceID string, ruleID string, ignoredErrors ...[]uint32) (*dpdk.FirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteFirewallRuleError != nil {
		return nil, m.deleteFirewallRuleError
	}
	return nil, nil
}

// =============================================================================
// System Operations (rarely used by NetworkInterface controller)
// =============================================================================

func (m *DPDKClientMock) CheckInitialized(ctx context.Context, ignoredErrors ...[]uint32) (*dpdk.Initialized, error) {
	return &dpdk.Initialized{}, nil
}

func (m *DPDKClientMock) Initialize(ctx context.Context, ignoredErrors ...[]uint32) (*dpdk.Initialized, error) {
	return &dpdk.Initialized{}, nil
}

func (m *DPDKClientMock) GetVni(ctx context.Context, vni uint32, vniType uint8, ignoredErrors ...[]uint32) (*dpdk.Vni, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getVniCalls++

	if m.getVniError != nil {
		return nil, m.getVniError
	}
	if m.getVniResponse != nil {
		return m.getVniResponse, nil
	}
	// Return nil, nil by default (simulates no VNI available)
	return nil, nil
}

func (m *DPDKClientMock) ResetVni(ctx context.Context, vni uint32, vniType uint8, ignoredErrors ...[]uint32) (*dpdk.Vni, error) {
	return nil, nil
}

func (m *DPDKClientMock) GetVersion(ctx context.Context, version *dpdk.Version, ignoredErrors ...[]uint32) (*dpdk.Version, error) {
	return &dpdk.Version{}, nil
}

func (m *DPDKClientMock) CaptureStart(ctx context.Context, capture *dpdk.CaptureStart, ignoredErrors ...[]uint32) (*dpdk.CaptureStart, error) {
	return capture, nil
}

func (m *DPDKClientMock) CaptureStop(ctx context.Context, ignoredErrors ...[]uint32) (*dpdk.CaptureStop, error) {
	return &dpdk.CaptureStop{}, nil
}

func (m *DPDKClientMock) CaptureStatus(ctx context.Context, ignoredErrors ...[]uint32) (*dpdk.CaptureStatus, error) {
	return &dpdk.CaptureStatus{}, nil
}

// =============================================================================
// Helper Methods for Test Configuration
// =============================================================================

// SetGetInterfaceResponse sets the response for GetInterface calls
func (m *DPDKClientMock) SetGetInterfaceResponse(iface *dpdk.Interface, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getInterfaceResponse = iface
	m.getInterfaceError = err
}

// SetCreateInterfaceError sets an error for CreateInterface calls
func (m *DPDKClientMock) SetCreateInterfaceError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createInterfaceError = err
}

// SetListPrefixesResponse sets the response for ListPrefixes calls
func (m *DPDKClientMock) SetListPrefixesResponse(prefixes []dpdk.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listPrefixesResponse = &dpdk.PrefixList{Items: prefixes}
}

// SetListPrefixesError sets an error for ListPrefixes calls
func (m *DPDKClientMock) SetListPrefixesError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listPrefixesError = err
}

// SetListLoadBalancerPrefixesResponse sets the response for ListLoadBalancerPrefixes calls
func (m *DPDKClientMock) SetListLoadBalancerPrefixesResponse(prefixes []dpdk.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listLoadBalancerPrefixesResponse = &dpdk.PrefixList{Items: prefixes}
}

// SetListLoadBalancerPrefixesError sets an error for ListLoadBalancerPrefixes calls
func (m *DPDKClientMock) SetListLoadBalancerPrefixesError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listLoadBalancerPrefixesError = err
}

// SetListFirewallRulesResponse sets the response for ListFirewallRules calls
func (m *DPDKClientMock) SetListFirewallRulesResponse(rules []dpdk.FirewallRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listFirewallRulesResponse = &dpdk.FirewallRuleList{Items: rules}
}

// SetListFirewallRulesError sets an error for ListFirewallRules calls
func (m *DPDKClientMock) SetListFirewallRulesError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listFirewallRulesError = err
}

// SetDeleteFirewallRuleError sets an error for DeleteFirewallRule calls
func (m *DPDKClientMock) SetDeleteFirewallRuleError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteFirewallRuleError = err
}

// SetGetNatResponse sets the response for GetNat calls
func (m *DPDKClientMock) SetGetNatResponse(nat *dpdk.Nat, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getNatResponse = nat
	m.getNatError = err
}

// SetGetVirtualIPResponse sets the response for GetVirtualIP calls
func (m *DPDKClientMock) SetGetVirtualIPResponse(vip *dpdk.VirtualIP, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getVirtualIPResponse = vip
	m.getVirtualIPError = err
}

// SetDeleteVirtualIPError sets an error for DeleteVirtualIP calls
func (m *DPDKClientMock) SetDeleteVirtualIPError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteVirtualIPError = err
}

// SetDeletePrefixError sets an error for DeletePrefix calls
func (m *DPDKClientMock) SetDeletePrefixError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletePrefixError = err
}

// SetDeleteLoadBalancerPrefixError sets an error for DeleteLoadBalancerPrefix calls
func (m *DPDKClientMock) SetDeleteLoadBalancerPrefixError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLoadBalancerPrefixError = err
}

// SetDeleteInterfaceError sets an error for DeleteInterface calls
func (m *DPDKClientMock) SetDeleteInterfaceError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteInterfaceError = err
}

// SetDeleteNatError sets an error for DeleteNat calls
func (m *DPDKClientMock) SetDeleteNatError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteNatError = err
}

// SetCreateNatError sets an error for CreateNat calls
func (m *DPDKClientMock) SetCreateNatError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createNatError = err
}

// SetCreateVirtualIPError sets an error for CreateVirtualIP calls
func (m *DPDKClientMock) SetCreateVirtualIPError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createVirtualIPError = err
}

// SetListNeighborNatsResponse sets the response for ListNeighborNats calls
func (m *DPDKClientMock) SetListNeighborNatsResponse(nats []dpdk.Nat) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listNeighborNatsResponse = &dpdk.NatList{Items: nats}
}

// SetDeleteNeighborNatError sets an error for DeleteNeighborNat calls
func (m *DPDKClientMock) SetDeleteNeighborNatError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteNeighborNatError = err
}

// SetListNeighborNatsError sets an error for ListNeighborNats calls
func (m *DPDKClientMock) SetListNeighborNatsError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listNeighborNatsError = err
}

// SetCreatePrefixError sets an error for CreatePrefix calls
func (m *DPDKClientMock) SetCreatePrefixError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createPrefixError = err
}

// SetCreateLoadBalancerPrefixError sets an error for CreateLoadBalancerPrefix calls
func (m *DPDKClientMock) SetCreateLoadBalancerPrefixError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createLoadBalancerPrefixError = err
}

// SetListRoutesResponse sets the response for ListRoutes calls
func (m *DPDKClientMock) SetListRoutesResponse(routes []dpdk.Route) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listRoutesResponse = &dpdk.RouteList{Items: routes}
}

// SetDeleteRouteError sets an error for DeleteRoute calls
func (m *DPDKClientMock) SetDeleteRouteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteRouteError = err
}

// SetListRoutesError sets an error for ListRoutes calls
func (m *DPDKClientMock) SetListRoutesError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listRoutesError = err
}

// SetCreateRouteError sets an error for CreateRoute calls
func (m *DPDKClientMock) SetCreateRouteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createRouteError = err
}

// SetGetVniResponse sets the response for GetVni calls
func (m *DPDKClientMock) SetGetVniResponse(vni *dpdk.Vni) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getVniResponse = vni
}

// SetGetVniError sets an error for GetVni calls
func (m *DPDKClientMock) SetGetVniError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getVniError = err
}

// SetGetLoadBalancerResponse sets the response for GetLoadBalancer calls
func (m *DPDKClientMock) SetGetLoadBalancerResponse(lb *dpdk.LoadBalancer, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getLoadBalancerResponse = lb
	m.getLoadBalancerError = err
}

// SetCreateLoadBalancerError sets an error for CreateLoadBalancer calls
func (m *DPDKClientMock) SetCreateLoadBalancerError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createLoadBalancerError = err
}

// SetDeleteLoadBalancerError sets an error for DeleteLoadBalancer calls
func (m *DPDKClientMock) SetDeleteLoadBalancerError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLoadBalancerError = err
}

// =============================================================================
// Call Count Getters (for test assertions)
// =============================================================================

func (m *DPDKClientMock) GetInterfaceCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getInterfaceCalls
}

func (m *DPDKClientMock) CreateInterfaceCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createInterfaceCalls
}

func (m *DPDKClientMock) DeleteInterfaceCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteInterfaceCalls
}

func (m *DPDKClientMock) ListPrefixesCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listPrefixesCalls
}

func (m *DPDKClientMock) CreatePrefixCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createPrefixCalls
}

func (m *DPDKClientMock) DeletePrefixCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deletePrefixCalls
}

func (m *DPDKClientMock) ListLoadBalancerPrefixesCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listLoadBalancerPrefixesCalls
}

func (m *DPDKClientMock) CreateLoadBalancerPrefixCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createLoadBalancerPrefixCalls
}

func (m *DPDKClientMock) DeleteLoadBalancerPrefixCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteLoadBalancerPrefixCalls
}

func (m *DPDKClientMock) CreateNatCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createNatCalls
}

func (m *DPDKClientMock) DeleteNatCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteNatCalls
}

func (m *DPDKClientMock) CreateVirtualIPCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createVirtualIPCalls
}

func (m *DPDKClientMock) DeleteVirtualIPCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteVirtualIPCalls
}

func (m *DPDKClientMock) CreateRouteCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createRouteCalls
}

func (m *DPDKClientMock) DeleteRouteCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteRouteCalls
}

func (m *DPDKClientMock) ListRoutesCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listRoutesCalls
}

func (m *DPDKClientMock) ListNeighborNatsCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listNeighborNatsCalls
}

func (m *DPDKClientMock) GetVniCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getVniCalls
}

func (m *DPDKClientMock) DeleteNeighborNatCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteNeighborNatCalls
}

func (m *DPDKClientMock) GetLoadBalancerCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getLoadBalancerCalls
}

func (m *DPDKClientMock) CreateLoadBalancerCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createLoadBalancerCalls
}

func (m *DPDKClientMock) DeleteLoadBalancerCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleteLoadBalancerCalls
}

// =============================================================================
// Call Arguments Getters (for detailed assertions)
// =============================================================================

func (m *DPDKClientMock) GetCreateInterfaceArgs() []*dpdk.Interface {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createInterfaceArgs
}

func (m *DPDKClientMock) GetCreatePrefixArgs() []*dpdk.Prefix {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createPrefixArgs
}

func (m *DPDKClientMock) GetDeletePrefixArgs() []netip.Prefix {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deletePrefixArgs
}

func (m *DPDKClientMock) GetCreateLoadBalancerPrefixArgs() []*dpdk.LoadBalancerPrefix {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createLoadBalancerPrefixArgs
}

func (m *DPDKClientMock) GetCreateNatArgs() []*dpdk.Nat {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createNatArgs
}

func (m *DPDKClientMock) GetCreateVirtualIPArgs() []*dpdk.VirtualIP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createVirtualIPArgs
}

func (m *DPDKClientMock) GetCreateLoadBalancerArgs() []*dpdk.LoadBalancer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.createLoadBalancerArgs
}

// shouldIgnoreError checks if an error should be ignored based on the ignoredErrors parameter
func shouldIgnoreError(err error, ignoredErrors [][]uint32) bool {
	if err == nil {
		return false
	}

	// Flatten the ignoredErrors slices
	var codes []uint32
	for _, slice := range ignoredErrors {
		codes = append(codes, slice...)
	}

	// Check if the error matches any of the ignored codes
	if len(codes) > 0 && dpdkerrors.IsStatusErrorCode(err, codes...) {
		return true
	}

	return false
}
