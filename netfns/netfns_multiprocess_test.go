// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package netfns

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jaypipes/ghw"
	"k8s.io/apimachinery/pkg/types"
)

// TestMultiProcessClaims simulates multiple processes by creating multiple file stores
// that access the same directory, simulating the multi-process scenario without
// needing to spin up separate processes
func TestMultiProcessClaims(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "netfns-multiprocess-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some test addresses
	var addresses []ghw.PCIAddress
	for i := 0; i < 5; i++ {
		addr := *ghw.PCIAddressFromString(fmt.Sprintf("0000:00:%02x.0", i))
		addresses = append(addresses, addr)
	}

	// Create multiple stores (simulating different processes)
	const numManagers = 3
	managers := make([]*Manager, numManagers)

	for i := 0; i < numManagers; i++ {
		store, err := NewFileClaimStore(tempDir, false)
		if err != nil {
			t.Fatalf("Failed to create store %d: %v", i, err)
		}

		manager, err := NewManager(store, addresses)
		if err != nil {
			t.Fatalf("Failed to create manager %d: %v", i, err)
		}

		managers[i] = manager
	}

	// Each "process" claims its own unique address
	for i, manager := range managers {
		uid := types.UID(fmt.Sprintf("multiprocess-claim-%d", i))
		addr, err := manager.GetOrClaim(uid)
		if err != nil {
			t.Fatalf("Manager %d failed to claim: %v", i, err)
		}
		t.Logf("Manager %d claimed address %s", i, addr)
	}

	// Verify all claims exist in the filesystem
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read tempDir: %v", err)
	}

	// Count claim files (skipping the lock file)
	claimCount := 0
	for _, file := range files {
		if file.Name() != lockFile {
			claimCount++
		}
	}

	if claimCount != numManagers {
		t.Errorf("Expected %d claim files, found %d", numManagers, claimCount)
	}

	// Test a single address scenario where only one manager can succeed
	singleDir, err := os.MkdirTemp("", "netfns-single-test-")
	if err != nil {
		t.Fatalf("Failed to create single test dir: %v", err)
	}
	defer os.RemoveAll(singleDir)

	// Create a single address
	singleAddr := []ghw.PCIAddress{*ghw.PCIAddressFromString("0000:00:00.0")}

	// Create multiple managers for the single address
	singleManagers := make([]*Manager, numManagers)
	for i := 0; i < numManagers; i++ {
		store, err := NewFileClaimStore(singleDir, false)
		if err != nil {
			t.Fatalf("Failed to create single store %d: %v", i, err)
		}

		manager, err := NewManager(store, singleAddr)
		if err != nil {
			t.Fatalf("Failed to create single manager %d: %v", i, err)
		}

		singleManagers[i] = manager
	}

	// Have all managers try to claim the single address concurrently
	successCount := 0
	failCount := 0

	for i, manager := range singleManagers {
		uid := types.UID(fmt.Sprintf("single-claim-%d", i))
		_, err := manager.GetOrClaim(uid)
		if err == nil {
			successCount++
			t.Logf("Manager %d succeeded in claiming single address", i)
		} else {
			failCount++
			// Should fail with no address available
			if !errors.Is(err, ErrNoAddressAvailable) {
				t.Errorf("Manager %d failed with unexpected error: %v", i, err)
			}
		}
	}

	// Verify only one manager succeeded
	if successCount != 1 {
		t.Errorf("Expected exactly 1 successful claim for single address, got %d", successCount)
	}

	if failCount != numManagers-1 {
		t.Errorf("Expected %d failures for single address, got %d", numManagers-1, failCount)
	}

	// Check the files in the single directory
	singleFiles, err := os.ReadDir(singleDir)
	if err != nil {
		t.Fatalf("Failed to read singleDir: %v", err)
	}

	// Count non-lock files
	singleClaimCount := 0
	for _, file := range singleFiles {
		if file.Name() != lockFile {
			singleClaimCount++
		}
	}

	if singleClaimCount != 1 {
		t.Errorf("Expected exactly 1 claim file for single address, found %d", singleClaimCount)
	}
}
