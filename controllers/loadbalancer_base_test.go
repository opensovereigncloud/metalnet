// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"net/netip"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/controllers/mocks"
	"github.com/ironcore-dev/metalnet/internal"
	"github.com/ironcore-dev/metalnet/ipv6manager"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Shared test variables and helpers for LoadBalancer controller unit tests.
// These are used across all test files in the loadbalancer_*_test.go suite.
//
// Test Organization:
// - loadbalancer_base_test.go: Shared setup, variables, and helper functions
// - loadbalancer_creation_test.go: LoadBalancer creation and validation tests
// - loadbalancer_deletion_test.go: LoadBalancer deletion and cleanup tests
// - loadbalancer_error_test.go: Error recovery and error path tests
// - loadbalancer_ipv6_test.go: IPv6 support tests
//
// Note: This file provides helpers for LoadBalancer tests.
// It accesses global variables k8sClient and testNode from suite_test.go.

// setupLoadBalancerTest initializes the test environment for LoadBalancer tests.
// It creates a namespace, prepares a network and loadbalancer object, initializes mocks, and returns the reconciler ready for testing.
//
// Returns:
//   - ctx: Test context
//   - ns: Created namespace (to be cleaned up with AfterEach)
//   - network: Network object (already created in k8s)
//   - loadBalancer: LoadBalancer object template (not yet created in k8s - tests must create it)
//   - reconciler: Configured LoadBalancerReconciler with mocks
//   - dpdkMock: DPDK client mock for injecting test behavior
//   - routeUtilMock: RouteUtil mock for route announcement testing
func setupLoadBalancerTest() (
	ctx context.Context,
	ns *corev1.Namespace,
	network *metalnetv1alpha1.Network,
	loadBalancer *metalnetv1alpha1.LoadBalancer,
	reconciler *LoadBalancerReconciler,
	dpdkMock *mocks.DPDKClientMock,
	routeUtilMock *mocks.RouteUtilMock,
) {
	ctx = context.Background()

	// Initialize IPv6Manager with test CIDR (required for underlay IP generation)
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

	// Create network object first (LoadBalancer requires Network reference)
	network = createTestNetwork(ns.Name)
	Expect(k8sClient.Create(ctx, network)).To(Succeed())

	// Create LoadBalancer object with sensible test defaults (not created in k8s yet)
	// Individual tests are responsible for creating the LoadBalancer object
	loadBalancer = createTestLoadBalancer(ns.Name, network.Name)

	// Initialize mocks
	dpdkMock = mocks.NewDPDKClientMock()
	routeUtilMock = mocks.NewRouteUtilMock()

	// Initialize MetalnetCache for LoadBalancer tests (used for network lookups)
	metalnetCache := internal.NewMetalnetCache(nil)

	// Create reconciler with mocks and HA controller fields
	reconciler = &LoadBalancerReconciler{
		Client:            k8sClient, // global from suite_test.go
		APIReader:         k8sClient, // global from suite_test.go
		Scheme:            scheme.Scheme,
		DPDK:              dpdkMock,
		RouteUtil:         routeUtilMock,
		MetalnetCache:     metalnetCache,
		NodeName:          testNode, // global from suite_test.go
		PublicVNI:         100,      // Public VNI for route announcements
		EnableIPv6Support: true,     // IPv6 enabled by default for tests
		ControllerID:      "controller-a",
		ControllerHash:    "test-hash-a",
		ReadyNeeded:       1, // Single controller for basic tests (will be 2 for HA tests)
		Control: &control.ReconcileControl{
			SkipReconcile: false,
		},
	}

	return ctx, ns, network, loadBalancer, reconciler, dpdkMock, routeUtilMock
}

// cleanupLoadBalancerTest performs cleanup after each test.
// It deletes the namespace and resets all mocks to their initial state.
// This overload accepts mocks for explicit cleanup and reset.
func cleanupLoadBalancerTest(
	ctx context.Context,
	ns *corev1.Namespace,
	dpdkMock *mocks.DPDKClientMock,
	routeUtilMock *mocks.RouteUtilMock,
) {
	// Cleanup namespace (k8sClient is global from suite_test.go)
	Expect(k8sClient.Delete(ctx, ns)).To(Succeed())

	// Reset mocks
	dpdkMock.Reset()
	routeUtilMock.Reset()

	// Reset IPv6Manager singleton state
	ipv6manager.ResetForTest()
}

// cleanupLoadBalancerTestNoMocks performs cleanup without resetting mocks.
// Use this when you need to maintain mock state or perform custom cleanup.
func cleanupLoadBalancerTestNoMocks(
	ctx context.Context,
	ns *corev1.Namespace,
) {
	// Cleanup namespace (k8sClient is global from suite_test.go)
	Expect(k8sClient.Delete(ctx, ns)).To(Succeed())

	// Reset IPv6Manager singleton state
	ipv6manager.ResetForTest()
}

// reconcileLoadBalancerUntilDone reconciles a LoadBalancer until completion.
// This is needed because reconciliation may have multiple stages:
// 1. First reconcile: Create IP reservations -> requeue
// 2. Second reconcile: Apply LoadBalancer configuration to DPDK
//
// Returns an error if reconciliation fails or doesn't complete within maxAttempts.
func reconcileLoadBalancerUntilDone(reconciler *LoadBalancerReconciler, name, namespace string, ctx context.Context) error {
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

// expectLoadBalancerFinalizer verifies that the LoadBalancer object has the expected finalizer.
// The finalizer format with HA support: "networking.metalnet.onmetal.de/loadBalancer-<controllerID>"
// Example: "networking.metalnet.onmetal.de/loadBalancer-controller-a"
func expectLoadBalancerFinalizer(ctx context.Context, loadBalancer *metalnetv1alpha1.LoadBalancer) {
	// Fetch latest version from API server
	Expect(k8sClient.Get(ctx, types.NamespacedName{
		Name:      loadBalancer.Name,
		Namespace: loadBalancer.Namespace,
	}, loadBalancer)).To(Succeed())

	// Check for LoadBalancer finalizer with controller-specific suffix
	// Expected format: "networking.metalnet.onmetal.de/loadBalancer-controller-a"
	Expect(loadBalancer.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.onmetal.de/loadBalancer-controller-a"))
}

// createTestLoadBalancer creates a LoadBalancer object with sensible test defaults.
// Uses standard test IP (11.5.5.1), TCP/UDP ports 80, and references the provided network.
func createTestLoadBalancer(namespace, networkName string) *metalnetv1alpha1.LoadBalancer {
	return &metalnetv1alpha1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-loadbalancer",
			Namespace: namespace,
		},
		Spec: metalnetv1alpha1.LoadBalancerSpec{
			NetworkRef: corev1.LocalObjectReference{Name: networkName},
			LBtype:     metalnetv1alpha1.LoadBalancerTypePublic,
			IPFamily:   corev1.IPv4Protocol,
			IP: metalnetv1alpha1.IP{
				Addr: netip.MustParseAddr("11.5.5.1"),
			},
			Ports: []metalnetv1alpha1.LBPort{
				{Protocol: string(corev1.ProtocolTCP), Port: 80},
				{Protocol: string(corev1.ProtocolUDP), Port: 80},
			},
			NodeName: &testNode,
		},
	}
}

// Note: createTestNetwork and createMockRouterAddr are defined in network_base_test.go
// to avoid redeclaration. They are shared between NetworkInterface and LoadBalancer tests.
