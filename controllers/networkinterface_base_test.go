// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	"github.com/ironcore-dev/metalnet/ipv6manager"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Shared test variables and helpers for NetworkInterface controller unit tests.
// These are used across all test files in the networkinterface_*_test.go suite.
//
// Test Organization:
// - networkinterface_test_base.go: Shared setup, variables, and helper functions
// - networkinterface_crud_test.go: Interface creation, deletion, and edge cases
// - networkinterface_ipv6_test.go: IPv6 support tests
// - networkinterface_reservation_test.go: IP reservation management tests
// - networkinterface_prefix_lb_test.go: Prefix and LoadBalancer target reconciliation
// - networkinterface_vip_nat_test.go: VirtualIP and NAT functionality tests
// - networkinterface_ha_test.go: High Availability dual-controller tests
// - networkinterface_error_test.go: Error recovery and error path tests

// Note: This file provides helpers for NetworkInterface tests.
// It accesses global variables k8sClient and testNode from suite_test.go.

// setupNetworkInterfaceTest initializes the test environment for NetworkInterface tests.
// It creates a namespace, network, initializes mocks, and returns the reconciler ready for testing.
//
// Returns:
//   - ctx: Test context
//   - ns: Created namespace (to be cleaned up with AfterEach)
//   - network: Created network object
//   - reconciler: Configured NetworkInterfaceReconciler with mocks
//   - dpdkMock: DPDK client mock for injecting test behavior
//   - routeUtilMock: RouteUtil mock for route announcement testing
//   - netFnsMock: NetFns manager mock for network function testing
func setupNetworkInterfaceTest() (
	ctx context.Context,
	ns *corev1.Namespace,
	network *metalnetv1alpha1.Network,
	reconciler *NetworkInterfaceReconciler,
	dpdkMock *mocks.DPDKClientMock,
	routeUtilMock *mocks.RouteUtilMock,
	netFnsMock *mocks.NetFnsManagerMock,
) {
	ctx = context.Background()

	// Initialize IPv6Manager with ULA address range for privacy
	// ULA range: fd00::/8 - using fd00:1234:5678:abcd for test consistency
	// d080 indicates primary underlay pool
	ipv6mgr := ipv6manager.GetInstance()
	ipv6mgr.SetCIDR("fd00:1234:5678:abcd:d080::/88")

	// Create namespace for tests
	ns = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "testns-",
		},
	}
	// k8sClient is a global variable from suite_test.go
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())

	// Create network
	network = &metalnetv1alpha1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-network",
			Namespace: ns.Name,
		},
		Spec: metalnetv1alpha1.NetworkSpec{
			ID: 100,
		},
	}
	Expect(k8sClient.Create(ctx, network)).To(Succeed())

	// Initialize mocks
	dpdkMock = mocks.NewDPDKClientMock()
	routeUtilMock = mocks.NewRouteUtilMock()
	netFnsMock = mocks.NewNetFnsManagerMock()

	// Create reconciler with mocks and HA controller fields
	reconciler = &NetworkInterfaceReconciler{
		Client:            k8sClient, // global from suite_test.go
		APIReader:         k8sClient, // global from suite_test.go
		EventRecorder:     &record.FakeRecorder{},
		Scheme:            scheme.Scheme,
		DPDK:              dpdkMock,
		RouteUtil:         routeUtilMock,
		NetFnsManager:     netFnsMock,
		NodeName:          testNode, // global from suite_test.go
		PublicVNI:         100,
		EnableIPv6Support: false,
		ControllerID:      "controller-a", // HA: Controller identifier
		ControllerHash:    "test-hash-a",  // HA: Instance hash
		ReadyNeeded:       1,              // HA: Single controller for basic tests (will be 2 for HA tests)
		Control: &control.ReconcileControl{
			SkipReconcile: false,
		},
	}

	return ctx, ns, network, reconciler, dpdkMock, routeUtilMock, netFnsMock
}

// cleanupNetworkInterfaceTest performs cleanup after each test.
// It deletes the namespace and resets all mocks to their initial state.
func cleanupNetworkInterfaceTest(
	ctx context.Context,
	ns *corev1.Namespace,
	dpdkMock *mocks.DPDKClientMock,
	routeUtilMock *mocks.RouteUtilMock,
	netFnsMock *mocks.NetFnsManagerMock,
) {
	// Cleanup namespace (k8sClient is global from suite_test.go)
	Expect(k8sClient.Delete(ctx, ns)).To(Succeed())

	// Reset mocks
	dpdkMock.Reset()
	routeUtilMock.Reset()
	netFnsMock.Reset()

	// Reset IPv6Manager singleton for next test
	ipv6manager.ResetForTest()
}

// reconcileUntilDone reconciles an interface until completion.
// This is needed because reconciliation now has multiple stages:
//  1. First reconcile: Create reservations, requeue
//  2. Second reconcile: Actually apply the interface
//
// Returns an error if reconciliation fails or doesn't complete within maxAttempts.
func reconcileUntilDone(reconciler *NetworkInterfaceReconciler, name, namespace string, ctx context.Context) error {
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		result, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      name,
				Namespace: namespace,
			},
		})
		if err != nil {
			return err
		}
		if !result.Requeue && result.RequeueAfter == 0 {
			return nil // Reconciliation complete
		}
	}
	return fmt.Errorf("reconciliation did not complete after %d attempts", maxAttempts)
}
