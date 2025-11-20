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
	"github.com/ironcore-dev/metalnet/metalbond"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Shared test variables and helpers for Network controller unit tests.
// These are used across all test files in the network_*_test.go suite.
//
// Test Organization:
// - network_base_test.go: Shared setup, variables, and helper functions
// - network_creation_test.go: Network creation and validation tests
// - network_deletion_test.go: Network deletion and cleanup tests
// - network_subscription_test.go: MetalBond subscription tests
// - network_error_test.go: Error recovery and error path tests
// - network_ipv6_test.go: IPv6 support tests
//
// Note: This file provides helpers for Network tests.
// It accesses global variables k8sClient and testNode from suite_test.go.

// setupNetworkTest initializes the test environment for Network tests.
// It creates a namespace, prepares a network object, initializes mocks, and returns the reconciler ready for testing.
//
// Returns:
//   - ctx: Test context
//   - ns: Created namespace (to be cleaned up with AfterEach)
//   - network: Network object template (not yet created in k8s - tests must create it)
//   - reconciler: Configured NetworkReconciler with mocks
//   - dpdkMock: DPDK client mock for injecting test behavior
//   - routeUtilMock: RouteUtil mock for route announcement testing
func setupNetworkTest() (
	ctx context.Context,
	ns *corev1.Namespace,
	network *metalnetv1alpha1.Network,
	reconciler *NetworkReconciler,
	dpdkMock *mocks.DPDKClientMock,
	routeUtilMock *mocks.RouteUtilMock,
) {
	ctx = context.Background()

	// Create namespace for tests
	ns = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "testns-",
		},
	}
	// k8sClient is a global variable from suite_test.go
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())

	// Create network object with sensible test defaults (not created in k8s yet)
	// Individual tests are responsible for creating the Network object
	network = createTestNetwork(ns.Name)

	// Initialize mocks
	dpdkMock = mocks.NewDPDKClientMock()
	routeUtilMock = mocks.NewRouteUtilMock()

	// Create default router address for test
	defaultRouterAddr := createMockRouterAddr()

	// Create reconciler with mocks and HA controller fields
	// Note: MetalnetCache is mostly unused (peering is commented out), passing nil
	reconciler = &NetworkReconciler{
		Client:            k8sClient, // global from suite_test.go
		APIReader:         k8sClient, // global from suite_test.go
		Scheme:            scheme.Scheme,
		DPDK:              dpdkMock,
		RouteUtil:         routeUtilMock,
		MetalnetCache:     nil,
		DefaultRouterAddr: defaultRouterAddr,
		NodeName:          testNode, // global from suite_test.go
		EnableIPv6Support: true,     // IPv6 enabled by default for tests
		ControllerID:      "controller-a",
		ControllerHash:    "test-hash-a",
		ReadyNeeded:       1, // Single controller for basic tests (will be 2 for HA tests)
		Control: &control.ReconcileControl{
			SkipReconcile: false,
		},
	}

	return ctx, ns, network, reconciler, dpdkMock, routeUtilMock
}

// cleanupNetworkTest performs cleanup after each test.
// It deletes the namespace and resets all mocks to their initial state.
// This overload accepts mocks for explicit cleanup and reset.
func cleanupNetworkTest(
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
}

// cleanupNetworkTestNoMocks performs cleanup without resetting mocks.
// Use this when you need to maintain mock state or perform custom cleanup.
func cleanupNetworkTestNoMocks(
	ctx context.Context,
	ns *corev1.Namespace,
) {
	// Cleanup namespace (k8sClient is global from suite_test.go)
	Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
}

// reconcileNetworkUntilDone reconciles a network until completion.
// This is needed because reconciliation may have multiple stages.
//
// Returns an error if reconciliation fails or doesn't complete within maxAttempts.
func reconcileNetworkUntilDone(reconciler *NetworkReconciler, name, namespace string, ctx context.Context) error {
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

// expectNetworkFinalizer verifies that the Network object has the expected finalizer.
// The finalizer format includes node name and controller ID: "networking.metalnet.ironcore.dev/network-{nodeName}-{controllerID}"
func expectNetworkFinalizer(ctx context.Context, network *metalnetv1alpha1.Network) {
	// Fetch latest version from API server
	Expect(k8sClient.Get(ctx, types.NamespacedName{
		Name:      network.Name,
		Namespace: network.Namespace,
	}, network)).To(Succeed())

	// Check for network finalizer with node name and controller ID suffix
	// Expected format: "networking.metalnet.ironcore.dev/network-testNode-controller-a"
	Expect(network.ObjectMeta.Finalizers).To(ContainElement("networking.metalnet.ironcore.dev/network-testNode-controller-a"))
}

// createTestNetwork creates a Network object with sensible test defaults.
// Uses VNI 123 and standard test namespace.
func createTestNetwork(namespace string) *metalnetv1alpha1.Network {
	return &metalnetv1alpha1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-network",
			Namespace: namespace,
		},
		Spec: metalnetv1alpha1.NetworkSpec{
			ID: 123, // Test VNI
		},
	}
}

// createMockRouterAddr creates a valid DefaultRouterAddress for testing.
// Returns a router address with 10.0.0.1 and public VNI 100.
func createMockRouterAddr() *metalbond.DefaultRouterAddress {
	routerAddr, err := netip.ParseAddr("10.0.0.1")
	Expect(err).NotTo(HaveOccurred())

	return &metalbond.DefaultRouterAddress{
		RouterAddress:    routerAddr,
		PublicVNI:        100,
		SetBySubsciption: false,
	}
}
