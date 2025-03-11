// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package netfns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jaypipes/ghw"
	"k8s.io/apimachinery/pkg/types"
)

// TestConcurrentClaims tests that concurrent claims are handled correctly
func TestConcurrentClaims(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "netfns-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create two stores pointing to the same directory
	store1, err := NewFileClaimStore(tempDir, false)
	if err != nil {
		t.Fatalf("Failed to create store1: %v", err)
	}

	store2, err := NewFileClaimStore(tempDir, false)
	if err != nil {
		t.Fatalf("Failed to create store2: %v", err)
	}

	// Create a set of test addresses
	var addresses []ghw.PCIAddress
	for i := 0; i < 20; i++ {
		addr := *ghw.PCIAddressFromString(fmt.Sprintf("0000:00:%02x.0", i))
		addresses = append(addresses, addr)
	}

	// Create two managers pointing to the same directory
	manager1, err := NewManager(store1, addresses)
	if err != nil {
		t.Fatalf("Failed to create manager1: %v", err)
	}

	manager2, err := NewManager(store2, addresses)
	if err != nil {
		t.Fatalf("Failed to create manager2: %v", err)
	}

	// Number of goroutines to test with
	const numGoroutines = 5
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // For both managers

	// Channel to collect results
	resultCh := make(chan types.UID, numGoroutines*2)

	// Claims from manager1
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			uid := types.UID(fmt.Sprintf("manager1-claim-%d", i))
			_, err := manager1.GetOrClaim(uid)
			if err != nil {
				t.Errorf("Manager1 failed to claim address for %s: %v", uid, err)
				return
			}
			resultCh <- uid
		}(i)
	}

	// Claims from manager2
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			uid := types.UID(fmt.Sprintf("manager2-claim-%d", i))
			_, err := manager2.GetOrClaim(uid)
			if err != nil {
				t.Errorf("Manager2 failed to claim address for %s: %v", uid, err)
				return
			}
			resultCh <- uid
		}(i)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(resultCh)

	// Collect and check results
	claimedUIDs := make(map[types.UID]struct{})
	for uid := range resultCh {
		claimedUIDs[uid] = struct{}{}
	}

	// Check if we got all the expected claims
	if len(claimedUIDs) != numGoroutines*2 {
		t.Errorf("Expected %d successful claims, got %d", numGoroutines*2, len(claimedUIDs))
	}

	// Read the claims from the filesystem directly
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read tempDir: %v", err)
	}

	fileCount := 0
	for _, file := range files {
		if file.Name() != lockFile {
			fileCount++
		}
	}

	if fileCount != numGoroutines*2 {
		t.Errorf("Expected %d claim files, found %d", numGoroutines*2, fileCount)
	}

	// Test for double-claiming (should get the same address)
	t.Run("DoubleClaim", func(t *testing.T) {
		uid := types.UID("double-claim-test")

		// First claim
		addr1, err := manager1.GetOrClaim(uid)
		if err != nil {
			t.Fatalf("First claim failed: %v", err)
		}

		// Second claim from different manager
		addr2, err := manager2.GetOrClaim(uid)
		if err != nil {
			t.Fatalf("Second claim failed: %v", err)
		}

		// Addresses should be the same
		if addr1.String() != addr2.String() {
			t.Errorf("Double claim returned different addresses: %s vs %s", addr1.String(), addr2.String())
		}
	})

	// Test concurrent release
	t.Run("ConcurrentRelease", func(t *testing.T) {
		uid := types.UID("release-test")

		// First create a claim
		_, err := manager1.GetOrClaim(uid)
		if err != nil {
			t.Fatalf("Failed to create claim for release test: %v", err)
		}

		// Release concurrently from both managers
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = manager1.Release(uid) // Ignore errors, only one should succeed
		}()

		go func() {
			defer wg.Done()
			_ = manager2.Release(uid) // Ignore errors, only one should succeed
		}()

		wg.Wait()

		// Check if the claim is gone
		_, err = manager1.Get(uid)
		if err == nil {
			t.Errorf("Claim still exists after release")
		}
	})

	// Test claiming the last address with proper synchronization
	t.Run("LastAddressClaim", func(t *testing.T) {
		// Create a new directory and managers with only one address
		raceDir, err := os.MkdirTemp("", "netfns-race-test-")
		if err != nil {
			t.Fatalf("Failed to create race temp dir: %v", err)
		}
		defer os.RemoveAll(raceDir)

		// Create only one address
		singleAddr := []ghw.PCIAddress{*ghw.PCIAddressFromString("0000:00:00.0")}

		// First claim the address with one UID
		store1, err := NewFileClaimStore(raceDir, false)
		if err != nil {
			t.Fatalf("Failed to create store1: %v", err)
		}

		manager1, err := NewManager(store1, singleAddr)
		if err != nil {
			t.Fatalf("Failed to create manager1: %v", err)
		}

		uid1 := types.UID("first-claim")
		addr1, err := manager1.GetOrClaim(uid1)
		if err != nil {
			t.Fatalf("First claim failed: %v", err)
		}

		// Try to claim with a different UID, should fail
		uid2 := types.UID("second-claim")
		_, err = manager1.GetOrClaim(uid2)
		if err == nil {
			t.Fatalf("Second claim with no available addresses should have failed")
		}
		if !errors.Is(err, ErrNoAddressAvailable) {
			t.Fatalf("Expected ErrNoAddressAvailable, got: %v", err)
		}

		// Release the address
		err = manager1.Release(uid1)
		if err != nil {
			t.Fatalf("Failed to release address: %v", err)
		}

		// Now the claim should succeed
		addr2, err := manager1.GetOrClaim(uid2)
		if err != nil {
			t.Fatalf("Claim after release failed: %v", err)
		}

		// The addresses should be the same
		if addr1.String() != addr2.String() {
			t.Errorf("Expected same address after release/claim, got %s vs %s", addr1.String(), addr2.String())
		}
	})
}

// TestManagerReleaseAll tests that ReleaseAll works correctly
func TestManagerReleaseAll(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "netfns-releaseall-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileClaimStore(tempDir, false)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create some test addresses
	var addresses []ghw.PCIAddress
	for i := 0; i < 5; i++ {
		addr := *ghw.PCIAddressFromString(fmt.Sprintf("0000:00:%02x.0", i))
		addresses = append(addresses, addr)
	}

	manager, err := NewManager(store, addresses)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create some claims
	for i := 0; i < 5; i++ {
		uid := types.UID(fmt.Sprintf("claim-%d", i))
		_, err := manager.GetOrClaim(uid)
		if err != nil {
			t.Fatalf("Failed to create claim %s: %v", uid, err)
		}
	}

	// Create the lock file manually to simulate another process
	lockPath := filepath.Join(tempDir, lockFile)
	if err := os.WriteFile(lockPath, []byte("test"), filePerm); err != nil {
		t.Fatalf("Failed to create lock file: %v", err)
	}

	// Verify we have 5 claims + 1 lock file
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read tempDir: %v", err)
	}
	if len(files) != 6 {
		t.Errorf("Expected 6 files (5 claims + lock), got %d", len(files))
	}

	// Remove the lock file so ReleaseAll can work
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("Failed to remove lock file: %v", err)
	}

	// Release all claims
	if err := manager.ReleaseAll(); err != nil {
		t.Fatalf("ReleaseAll failed: %v", err)
	}

	// Verify all claims are gone (should only be 0 files)
	files, err = os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read tempDir: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("Expected 0 files after ReleaseAll, got %d", len(files))
	}
}

// TestFileLocking tests the lock mechanism directly
func TestFileLocking(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "netfns-lock-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileClaimStore(tempDir, false)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	fileStore, ok := store.(*fileClaimStore)
	if !ok {
		t.Fatalf("Expected fileClaimStore, got %T", store)
	}

	// Test acquiring a lock
	err = fileStore.acquireLock()
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Check if lock file exists
	lockPath := filepath.Join(tempDir, lockFile)
	_, err = os.Stat(lockPath)
	if err != nil {
		t.Fatalf("Lock file does not exist: %v", err)
	}

	// Test that acquiring a second lock fails
	store2, err := NewFileClaimStore(tempDir, false)
	if err != nil {
		t.Fatalf("Failed to create store2: %v", err)
	}

	fileStore2, ok := store2.(*fileClaimStore)
	if !ok {
		t.Fatalf("Expected fileClaimStore, got %T", store2)
	}

	err = fileStore2.acquireLock()
	if err == nil {
		t.Fatalf("Second lock acquisition should have failed")
	}

	// Release the lock
	err = fileStore.releaseLock()
	if err != nil {
		t.Fatalf("Failed to release lock: %v", err)
	}

	// Check lock file is gone
	_, err = os.Stat(lockPath)
	if !os.IsNotExist(err) {
		t.Fatalf("Lock file still exists after release")
	}

	// Now second store should be able to acquire the lock
	err = fileStore2.acquireLock()
	if err != nil {
		t.Fatalf("Failed to acquire lock after release: %v", err)
	}

	// Clean up
	_ = fileStore2.releaseLock()
}
