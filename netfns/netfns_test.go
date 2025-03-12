// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package netfns_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jaypipes/ghw"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ironcore-dev/metalnet/netfns"
)

func TestNetFNS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NetFNS Suite")
}

// Define labels for test organization
var CoreLabel = Label("core")
var MultiprocessLabel = Label("multiprocess")

var _ = Describe("FileClaimStore", CoreLabel, func() {
	const lockFile = ".lock"
	const filePerm = 0666
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "netfns-test-")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("Concurrent claims", func() {
		var store1, store2 netfns.ClaimStore
		var manager1, manager2 *netfns.Manager
		var addresses []ghw.PCIAddress

		BeforeEach(func() {
			var err error
			// Create two stores pointing to the same directory
			store1, err = netfns.NewFileClaimStore(tempDir, false)
			Expect(err).NotTo(HaveOccurred())

			store2, err = netfns.NewFileClaimStore(tempDir, false)
			Expect(err).NotTo(HaveOccurred())

			// Create a set of test addresses
			addresses = []ghw.PCIAddress{}
			for i := 0; i < 20; i++ {
				addr := *ghw.PCIAddressFromString(fmt.Sprintf("0000:00:%02x.0", i))
				addresses = append(addresses, addr)
			}

			// Create two managers pointing to the same directory
			manager1, err = netfns.NewManager(store1, addresses)
			Expect(err).NotTo(HaveOccurred())

			manager2, err = netfns.NewManager(store2, addresses)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle concurrent claims correctly", func() {
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
					Expect(err).NotTo(HaveOccurred(), "Manager1 failed to claim address for %s", uid)
					resultCh <- uid
				}(i)
			}

			// Claims from manager2
			for i := 0; i < numGoroutines; i++ {
				go func(i int) {
					defer wg.Done()
					uid := types.UID(fmt.Sprintf("manager2-claim-%d", i))
					_, err := manager2.GetOrClaim(uid)
					Expect(err).NotTo(HaveOccurred(), "Manager2 failed to claim address for %s", uid)
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
			Expect(claimedUIDs).To(HaveLen(numGoroutines*2), "Expected %d successful claims", numGoroutines*2)

			// Read the claims from the filesystem directly
			files, err := os.ReadDir(tempDir)
			Expect(err).NotTo(HaveOccurred(), "Failed to read tempDir")

			fileCount := 0
			for _, file := range files {
				if file.Name() != lockFile {
					fileCount++
				}
			}

			Expect(fileCount).To(Equal(numGoroutines*2), "Expected %d claim files", numGoroutines*2)
		})

		It("should return the same address for double claims", func() {
			uid := types.UID("double-claim-test")

			// First claim
			addr1, err := manager1.GetOrClaim(uid)
			Expect(err).NotTo(HaveOccurred(), "First claim failed")

			// Second claim from different manager
			addr2, err := manager2.GetOrClaim(uid)
			Expect(err).NotTo(HaveOccurred(), "Second claim failed")

			// Addresses should be the same
			Expect(addr1.String()).To(Equal(addr2.String()), "Double claim returned different addresses")
		})

		It("should handle concurrent release correctly", func() {
			uid := types.UID("release-test")

			// First create a claim
			_, err := manager1.GetOrClaim(uid)
			Expect(err).NotTo(HaveOccurred(), "Failed to create claim for release test")

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
			Expect(err).To(HaveOccurred(), "Claim still exists after release")
		})

		It("should fail when claiming the last available address", func() {
			// Create a new directory and managers with only one address
			raceDir, err := os.MkdirTemp("", "netfns-race-test-")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(raceDir)

			// Create only one address
			singleAddr := []ghw.PCIAddress{*ghw.PCIAddressFromString("0000:00:00.0")}

			// First claim the address with one UID
			store, err := netfns.NewFileClaimStore(raceDir, false)
			Expect(err).NotTo(HaveOccurred())

			manager, err := netfns.NewManager(store, singleAddr)
			Expect(err).NotTo(HaveOccurred())

			uid1 := types.UID("first-claim")
			addr1, err := manager.GetOrClaim(uid1)
			Expect(err).NotTo(HaveOccurred(), "First claim failed")

			// Try to claim with a different UID, should fail
			uid2 := types.UID("second-claim")
			_, err = manager.GetOrClaim(uid2)
			Expect(err).To(MatchError(netfns.ErrNoAddressAvailable), "Second claim with no available addresses should have failed")

			// Release the address
			err = manager.Release(uid1)
			Expect(err).NotTo(HaveOccurred(), "Failed to release address")

			// Now the claim should succeed
			addr2, err := manager.GetOrClaim(uid2)
			Expect(err).NotTo(HaveOccurred(), "Claim after release failed")

			// The addresses should be the same
			Expect(addr1.String()).To(Equal(addr2.String()), "Expected same address after release/claim")
		})
	})

	Context("ReleaseAll", func() {
		var store netfns.ClaimStore
		var manager *netfns.Manager
		var addresses []ghw.PCIAddress

		BeforeEach(func() {
			var err error
			store, err = netfns.NewFileClaimStore(tempDir, false)
			Expect(err).NotTo(HaveOccurred())

			// Create some test addresses
			addresses = []ghw.PCIAddress{}
			for i := 0; i < 5; i++ {
				addr := *ghw.PCIAddressFromString(fmt.Sprintf("0000:00:%02x.0", i))
				addresses = append(addresses, addr)
			}

			manager, err = netfns.NewManager(store, addresses)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should release all claims", func() {
			// Create some claims
			for i := 0; i < 5; i++ {
				uid := types.UID(fmt.Sprintf("claim-%d", i))
				_, err := manager.GetOrClaim(uid)
				Expect(err).NotTo(HaveOccurred(), "Failed to create claim %s", uid)
			}

			// Create the lock file manually to simulate another process
			lockPath := filepath.Join(tempDir, lockFile)
			err := os.WriteFile(lockPath, []byte("test"), filePerm)
			Expect(err).NotTo(HaveOccurred(), "Failed to create lock file")

			// Verify we have 5 claims + 1 lock file
			files, err := os.ReadDir(tempDir)
			Expect(err).NotTo(HaveOccurred(), "Failed to read tempDir")
			Expect(files).To(HaveLen(6), "Expected 6 files (5 claims + lock)")

			// Remove the lock file so ReleaseAll can work
			err = os.Remove(lockPath)
			Expect(err).NotTo(HaveOccurred(), "Failed to remove lock file")

			// Release all claims
			err = manager.ReleaseAll()
			Expect(err).NotTo(HaveOccurred(), "ReleaseAll failed")

			// Verify all claims are gone (should only be 0 files)
			files, err = os.ReadDir(tempDir)
			Expect(err).NotTo(HaveOccurred(), "Failed to read tempDir")
			Expect(files).To(HaveLen(0), "Expected 0 files after ReleaseAll")
		})
	})

	Context("FileLocking", func() {
		var store netfns.ClaimStore

		BeforeEach(func() {
			var err error
			store, err = netfns.NewFileClaimStore(tempDir, false)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle lock acquisition and release correctly", func() {
			// We test the lock mechanism indirectly since it's private
			// Create a claim which internally acquires a lock
			uid := types.UID("lock-test")
			addr := *ghw.PCIAddressFromString("0000:00:01.0")

			err := store.Create(uid, addr)
			Expect(err).NotTo(HaveOccurred(), "Failed to create claim (which acquires lock)")

			// Check if lock file exists and then goes away
			lockPath := filepath.Join(tempDir, lockFile)
			_, err = os.Stat(lockPath)
			Expect(os.IsNotExist(err)).To(BeTrue(), "Lock file should not exist after operation completes")

			// Create a second claim to ensure we can acquire the lock again
			uid2 := types.UID("lock-test-2")
			addr2 := *ghw.PCIAddressFromString("0000:00:02.0")

			err = store.Create(uid2, addr2)
			Expect(err).NotTo(HaveOccurred(), "Failed to create second claim (which acquires lock again)")
		})
	})
})

var _ = Describe("Multi-process claims", MultiprocessLabel, func() {
	const lockFile = ".lock"
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "netfns-multiprocess-test-")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	It("should simulate multiple processes by creating multiple file stores", func() {
		// Create some test addresses
		var addresses []ghw.PCIAddress
		for i := 0; i < 5; i++ {
			addr := *ghw.PCIAddressFromString(fmt.Sprintf("0000:00:%02x.0", i))
			addresses = append(addresses, addr)
		}

		// Create multiple stores (simulating different processes)
		const numManagers = 3
		managers := make([]*netfns.Manager, numManagers)

		for i := 0; i < numManagers; i++ {
			store, err := netfns.NewFileClaimStore(tempDir, false)
			Expect(err).NotTo(HaveOccurred(), "Failed to create store %d", i)

			manager, err := netfns.NewManager(store, addresses)
			Expect(err).NotTo(HaveOccurred(), "Failed to create manager %d", i)

			managers[i] = manager
		}

		// Each "process" claims its own unique address
		for i, manager := range managers {
			uid := types.UID(fmt.Sprintf("multiprocess-claim-%d", i))
			addr, err := manager.GetOrClaim(uid)
			Expect(err).NotTo(HaveOccurred(), "Manager %d failed to claim", i)
			GinkgoWriter.Printf("Manager %d claimed address %s\n", i, addr)
		}

		// Verify all claims exist in the filesystem
		files, err := os.ReadDir(tempDir)
		Expect(err).NotTo(HaveOccurred(), "Failed to read tempDir")

		// Count claim files (skipping the lock file)
		claimCount := 0
		for _, file := range files {
			if file.Name() != lockFile {
				claimCount++
			}
		}

		Expect(claimCount).To(Equal(numManagers), "Expected %d claim files", numManagers)
	})

	It("should handle contention with a single available address", func() {
		// Create a new directory for this test
		singleDir, err := os.MkdirTemp("", "netfns-single-test-")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(singleDir)

		// Create a single address
		singleAddr := []ghw.PCIAddress{*ghw.PCIAddressFromString("0000:00:00.0")}

		// Create multiple managers for the single address
		const numManagers = 3
		singleManagers := make([]*netfns.Manager, numManagers)
		for i := 0; i < numManagers; i++ {
			store, err := netfns.NewFileClaimStore(singleDir, false)
			Expect(err).NotTo(HaveOccurred(), "Failed to create single store %d", i)

			manager, err := netfns.NewManager(store, singleAddr)
			Expect(err).NotTo(HaveOccurred(), "Failed to create single manager %d", i)

			singleManagers[i] = manager
		}

		// Have all managers try to claim the single address sequentially
		successCount := 0
		failCount := 0

		for i, manager := range singleManagers {
			uid := types.UID(fmt.Sprintf("single-claim-%d", i))
			_, err := manager.GetOrClaim(uid)
			if err == nil {
				successCount++
				GinkgoWriter.Printf("Manager %d succeeded in claiming single address\n", i)
			} else {
				failCount++
				Expect(err).To(MatchError(netfns.ErrNoAddressAvailable),
					"Manager %d failed with unexpected error", i)
			}
		}

		// Verify only one manager succeeded
		Expect(successCount).To(Equal(1), "Expected exactly 1 successful claim for single address")
		Expect(failCount).To(Equal(numManagers-1), "Expected %d failures for single address", numManagers-1)

		// Check the files in the single directory
		singleFiles, err := os.ReadDir(singleDir)
		Expect(err).NotTo(HaveOccurred(), "Failed to read singleDir")

		// Count non-lock files
		singleClaimCount := 0
		for _, file := range singleFiles {
			if file.Name() != lockFile {
				singleClaimCount++
			}
		}

		Expect(singleClaimCount).To(Equal(1), "Expected exactly 1 claim file for single address")
	})
})
