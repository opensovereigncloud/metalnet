# Metalnet Development Guide

> **⚠️ IMPORTANT**: When test files are added, updated, or removed, update the "Test File Structure" section below.

## Test File Structure

**Last Updated**: 2025-11-16 | **Total Tests**: 179 | **Coverage**: 81.4%

### NetworkInterface Controller Tests
Location: `controllers/networkinterface_*_test.go`

| File | Tests | Purpose |
|------|-------|---------|
| `networkinterface_base_test.go` | helpers | Shared setup, cleanup, and reconciliation helpers |
| `networkinterface_conflict_test.go` | 7 | VirtualIP DNAT conflicts, prefix route conflicts, cleanup scenarios |
| `networkinterface_creation_test.go` | 9 | Interface creation, validation errors, operation failures |
| `networkinterface_deletion_test.go` | 19 | DPDK deletion errors, route withdrawal, firewall cleanup, orphaned resources |
| `networkinterface_dpdk_test.go` | 12 | DPDK device conversion paths (tap, PCI parsing, multiport, SysFS) |
| `networkinterface_feature_errors_test.go` | 15 | VirtualIP, NAT, Prefix, LoadBalancer route announcement/withdrawal errors |
| `networkinterface_ha_test.go` | 4 | High Availability dual-controller scenarios |
| `networkinterface_integration_errors_test.go` | 10 | Error recovery, combined failures, helper function edge cases |
| `networkinterface_ipv6_test.go` | 6 | IPv6 support, dual-stack, IPv6 route removal |
| `networkinterface_prefix_lb_test.go` | 14 | Prefix & LoadBalancer target reconciliation |
| `networkinterface_reservation_test.go` | 7 | IP reservation lifecycle and management |
| `networkinterface_vip_nat_test.go` | 5 | VirtualIP & NAT functionality |
| `networkinterface_virtlet_test.go` | 7 | Virtlet Machine UID lifecycle and grace period deletion |

**Adding New Tests**:
1. Open appropriate `networkinterface_*_test.go` file (or create new one following naming pattern)
2. Add test within existing `Context()` or create new one
3. Use `setupNetworkInterfaceTest()` in `BeforeEach` for consistent setup
4. Update this table when creating new test files

### Network Controller Tests
Location: `controllers/network_*_test.go`

| File | Tests | Purpose |
|------|-------|---------|
| `network_base_test.go` | helpers | Shared setup, cleanup, and reconciliation helpers for Network tests |
| `network_creation_test.go` | 10 | Finalizer management, VNI setup, route creation, Metalbond subscription |
| `network_deletion_test.go` | 10 | Network deletion, route cleanup, Metalbond unsubscription, error handling |
| `network_ha_test.go` | 4 | High Availability dual-controller coordination via finalizers and Metalbond |

### LoadBalancer Controller Tests
Location: `controllers/loadbalancer_*_test.go`

| File | Tests | Purpose |
|------|-------|---------|
| `loadbalancer_base_test.go` | helpers | Shared setup, cleanup, and reconciliation helpers for LoadBalancer tests |
| `loadbalancer_creation_test.go` | 17 | IP reservations, IPv6 underlay generation, DPDK creation, route announcement |
| `loadbalancer_deletion_test.go` | 12 | LoadBalancer deletion, route cleanup, DPDK cleanup, finalizer migration |
| `loadbalancer_ha_test.go` | 6 | High Availability dual-controller coordination via ControllerStatuses and IPv6 reservation |

### Other Controller Tests
- `controller_test.go` - Integration tests for Network/LoadBalancer controllers
- `suite_test.go` - Ginkgo test suite setup for integration tests

### Mock Infrastructure
Location: `controllers/mocks/`
- `dpdk_mock.go` - Stateful DPDK client mock with error injection
- `routeutil_mock.go` - Route announcement/withdrawal mock
- `netfns_mock.go` - Network function manager mock

---

## Testing and Coverage

### Running Unit Tests with Coverage

```bash
# Run all NetworkInterface tests with coverage
make test-coverage-container

# Run specific test category (example)
go test -v ./controllers --ginkgo.focus="NetworkInterfaceReconciler - IPv6"
```

**What it does**:
1. Builds container using `Dockerfile.coverage`
2. Runs NetworkInterfaceReconciler unit tests with coverage
3. Outputs per-function and overall coverage statistics
4. Saves logs to `/tmp/coverage-build.log`

### Viewing Coverage Results

```bash
# View full build log
tail -500 /tmp/coverage-build.log

# View coverage summary only
grep -A 10 "Coverage Summary" /tmp/coverage-build.log

# Run and filter output
make test-coverage-container 2>&1 | grep -A 50 "Coverage Summary\|Ran.*Specs"
```

### Other Test Commands

- `make test` - Run tests locally (requires envtest setup)
- `make test-compile-container` - Verify tests compile in container
- `make test-build-container` - Build test container with authentication

---

## Key Testing Patterns

### Stateful Mock Behavior

The DPDK mock tracks state across reconciliation cycles:
- `GetInterface` returns `NOT_FOUND` by default
- `CreateInterface` stores interface in memory
- Subsequent `GetInterface` returns stored interface
- `DeleteInterface` removes from memory

### Multi-Stage Reconciliation

NetworkInterface reconciliation happens in stages:
1. **First reconcile**: Create IP reservations → requeue
2. **Second reconcile**: Apply interface configuration to DPDK

**Use `reconcileUntilDone()` helper** to handle this automatically in tests.

### Error Injection

Mocks support error injection for testing error paths:
```go
dpdkMock.SetCreateInterfaceError(fmt.Errorf("DPDK failure"))
routeUtilMock.SetAnnounceRouteError(fmt.Errorf("route failed"))
```

---

## Coverage Goals & Progress

**Current**: 81.4% overall, 84.9% average function coverage
**Target**: >80% overall coverage (ACHIEVED!)

### Recent Improvements
- ✅ High Availability tests - Network and LoadBalancer dual-controller coordination (+0.1%)
- ✅ LoadBalancer controller unit tests - Complete coverage for creation/deletion (+10.7%)
- ✅ Network controller unit tests - Complete coverage for creation/deletion (+5.4%)
- ✅ Test file refactoring - Split monolithic files into focused modules (+1.2%)
- ✅ Orphaned DPDK resource cleanup tests (+0.5%)
- ✅ Error propagation bug fixes in deleteLBTargets/deletePrefixes (+0.3%)
- ✅ Firewall deletion error paths (+0.8%)
- ✅ NAT GetNat error handling (+0.3%)
- ✅ Virtlet Machine UID lifecycle (+2.3%)
- ✅ DPDK Device Conversion paths (+1.5%)

### Remaining Coverage Gaps
1. **Error Path Edge Cases** - Several 66-72% functions need additional scenarios
2. **IPv6 Route Removal** - Requires controller-level IPv6 configuration
3. **Success Paths** - Some functions only test error scenarios

---

## Troubleshooting

**Tests fail with "interface not found"**:
- Use `reconcileUntilDone()` instead of single `Reconcile()` call
- Let stateful mock handle interface existence automatically
- Don't configure GetInterface with manual 404 responses

**Reconciliation loops indefinitely**:
- Verify reservations created in first reconcile
- Check interface creation succeeds in second reconcile
- Use `reconcileUntilDone()` which has built-in loop protection

**Coverage not improving**:
- Ensure new test file ends with `_test.go`
- Check test is actually running (look for green dots in output)
- Verify reconciliation completes successfully
