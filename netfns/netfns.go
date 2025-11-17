// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package netfns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ironcore-dev/metalnet/sysfs"
	"github.com/jaypipes/ghw"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	perm       = 0777
	filePerm   = 0666
	lockFile   = ".lock"
	lockDelay  = 10 * time.Millisecond
	maxRetries = 50 // Increase retries with shorter delay for better concurrency
)

var (
	ErrClaimNotFound      = errors.New("claim not found")
	ErrClaimAlreadyExists = errors.New("claim already exists")
)

type Claim struct {
	UID     types.UID
	Address ghw.PCIAddress
}

type ClaimStore interface {
	Create(uid types.UID, addr ghw.PCIAddress) error
	Get(uid types.UID) (*ghw.PCIAddress, error)
	Delete(uid types.UID) (*ghw.PCIAddress, error)
	DeleteAll() error
	List() ([]Claim, error)
}

type fileClaimStore struct {
	rootDir    string
	isTAPStore bool
	mu         sync.Mutex // Protects lockFile operations
}

func NewFileClaimStore(rootDir string, isTAPStore bool) (ClaimStore, error) {
	if err := os.MkdirAll(rootDir, perm); err != nil {
		return nil, fmt.Errorf("error creating directory at %s: %w", rootDir, err)
	}
	return &fileClaimStore{
		rootDir:    rootDir,
		isTAPStore: isTAPStore,
	}, nil
}

// lockPath returns the path to the lock file
func (s *fileClaimStore) lockPath() string {
	return filepath.Join(s.rootDir, lockFile)
}

// acquireLock tries to create a lock file to ensure atomic operations
// Returns true if lock was acquired, false otherwise
func (s *fileClaimStore) acquireLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try to create lock file
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, filePerm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrLockTimeout
		}
		return fmt.Errorf("error creating lock file: %w", err)
	}

	// Write PID for debugging purposes
	_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
	if err != nil {
		_ = f.Close()
		_ = os.Remove(s.lockPath())
		return fmt.Errorf("error writing to lock file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(s.lockPath())
		return fmt.Errorf("error closing lock file: %w", err)
	}

	return nil
}

// releaseLock removes the lock file
func (s *fileClaimStore) releaseLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.lockPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("error removing lock file: %w", err)
	}
	return nil
}

// withLock executes the given function with a lock
func (s *fileClaimStore) withLock(fn func() error) error {
	// Try to acquire lock with retries
	for i := 0; i < maxRetries; i++ {
		err := s.acquireLock()
		if err == nil {
			// Lock acquired, execute function and release lock
			defer s.releaseLock()
			return fn()
		}

		if !errors.Is(err, ErrLockTimeout) {
			return err
		}

		// Lock timeout, wait and retry
		time.Sleep(lockDelay)
	}

	return ErrRetryExceeded
}

func (s *fileClaimStore) claimFile(uid types.UID) string {
	return filepath.Join(s.rootDir, string(uid))
}

func (s *fileClaimStore) Create(uid types.UID, addr ghw.PCIAddress) error {
	return s.withLock(func() error {
		filename := s.claimFile(uid)
		_, err := os.Stat(filename)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("error stat-ing %s: %w", filename, err)
		}
		if err == nil {
			return ErrClaimAlreadyExists
		}

		var data []byte
		if !s.isTAPStore {
			data = []byte(addr.String())
		} else {
			data = []byte(addr.Device)
		}

		return os.WriteFile(filename, data, filePerm)
	})
}

func (s *fileClaimStore) Get(uid types.UID) (*ghw.PCIAddress, error) {
	data, err := os.ReadFile(s.claimFile(uid))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("error reading pci address: %w", err)
		}
		return nil, ErrClaimNotFound
	}

	var addr *ghw.PCIAddress
	if !s.isTAPStore {
		addr = ghw.PCIAddressFromString(string(data))
	} else {
		addr = &ghw.PCIAddress{
			Device: string(data),
		}
	}
	if addr == nil {
		return nil, fmt.Errorf("invalid pci address %q", string(data))
	}

	return addr, nil
}

func (s *fileClaimStore) Delete(uid types.UID) (*ghw.PCIAddress, error) {
	var addr *ghw.PCIAddress
	var getErr error

	err := s.withLock(func() error {
		// Get the address first
		addr, getErr = s.Get(uid)
		if getErr != nil {
			return getErr
		}

		// Then remove the file
		if err := os.Remove(s.claimFile(uid)); err != nil {
			return fmt.Errorf("error deleting pci address: %w", err)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return addr, nil
}

func (s *fileClaimStore) DeleteAll() error {
	return s.withLock(func() error {
		entries, err := os.ReadDir(s.rootDir)
		if err != nil {
			return fmt.Errorf("error reading dir %s: %w", s.rootDir, err)
		}

		for _, entry := range entries {
			// Skip the lock file itself
			if entry.Name() == lockFile {
				continue
			}

			if err := os.Remove(filepath.Join(s.rootDir, entry.Name())); err != nil {
				return fmt.Errorf("error deleting claim file %s: %w", entry.Name(), err)
			}
		}

		return nil
	})
}

func (s *fileClaimStore) List() ([]Claim, error) {
	// We don't need to acquire the lock for the entire operation
	// Just for reading the directory
	entries, err := os.ReadDir(s.rootDir)
	if err != nil {
		return nil, fmt.Errorf("error reading dir %s: %w", s.rootDir, err)
	}

	var claims []Claim
	for _, entry := range entries {
		// Skip the lock file
		if entry.Name() == lockFile {
			continue
		}

		uid := types.UID(entry.Name())
		addr, err := s.Get(uid)
		if err != nil {
			// If the file disappeared, just skip it
			if errors.Is(err, ErrClaimNotFound) {
				continue
			}
			return nil, fmt.Errorf("[claim %s] error getting claim: %w", uid, err)
		}

		claims = append(claims, Claim{UID: uid, Address: *addr})
	}

	return claims, nil
}

var (
	ErrNoAddressAvailable = errors.New("no address available")
	ErrLockTimeout        = errors.New("timed out acquiring lock")
	ErrRetryExceeded      = errors.New("exceeded maximum retries")
)

// ManagerInterface defines the interface for managing PCI address claims
type ManagerInterface interface {
	Get(uid types.UID) (*ghw.PCIAddress, error)
	GetOrClaim(uid types.UID) (*ghw.PCIAddress, error)
	Release(uid types.UID) error
}

type Manager struct {
	store        ClaimStore
	allAddresses []ghw.PCIAddress
}

// NewManager creates a new Manager that relies solely on the filesystem
// rather than maintaining an in-memory state of available addresses
func NewManager(store ClaimStore, initAvailable []ghw.PCIAddress) (*Manager, error) {
	claims, err := store.List()
	if err != nil {
		return nil, fmt.Errorf("error listing claims: %w", err)
	}

	// Validate that all claims reference addresses in the provided set
	availableSet := sets.New(initAvailable...)
	for _, claim := range claims {
		if !availableSet.Has(claim.Address) {
			return nil, fmt.Errorf("claim %s references non-existent address %s", claim.UID, &claim.Address)
		}
	}

	return &Manager{
		store:        store,
		allAddresses: initAvailable,
	}, nil
}

// getAvailableAddresses returns the set of addresses that are not currently claimed
func (m *Manager) getAvailableAddresses() (sets.Set[ghw.PCIAddress], error) {
	// Start with all addresses
	available := sets.New(m.allAddresses...)

	// Remove claimed addresses
	claims, err := m.store.List()
	if err != nil {
		return nil, fmt.Errorf("error listing claims: %w", err)
	}

	for _, claim := range claims {
		available.Delete(claim.Address)
	}

	return available, nil
}

func (m *Manager) GetOrClaim(uid types.UID) (*ghw.PCIAddress, error) {
	// First try to get the existing claim
	addr, err := m.store.Get(uid)
	if err != nil && !errors.Is(err, ErrClaimNotFound) {
		return nil, fmt.Errorf("error getting claim: %w", err)
	}
	if err == nil {
		return addr, nil
	}

	// Try to claim a new address with retries
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Get current available addresses
		available, err := m.getAvailableAddresses()
		if err != nil {
			return nil, fmt.Errorf("error getting available addresses: %w", err)
		}

		// No addresses available
		if available.Len() == 0 {
			return nil, ErrNoAddressAvailable
		}

		// Pick an address
		newAddr := available.UnsortedList()[0]

		// Try to claim it
		err = m.store.Create(uid, newAddr)
		if err == nil {
			// Success!
			return &newAddr, nil
		}

		// If the error is not because the claim already exists, return the error
		if !errors.Is(err, ErrClaimAlreadyExists) {
			return nil, err
		}

		// Someone else created a claim in the meantime, retry
		time.Sleep(lockDelay)
	}

	return nil, ErrRetryExceeded
}

func (m *Manager) Get(uid types.UID) (*ghw.PCIAddress, error) {
	return m.store.Get(uid)
}

func (m *Manager) Release(uid types.UID) error {
	// We don't need to update any in-memory state since we always read from the filesystem
	_, err := m.store.Delete(uid)
	return err
}

func (m *Manager) ReleaseAll() error {
	// Simply delegate to the store
	return m.store.DeleteAll()
}

const (
	mellanoxVendorID         = "15b3"
	networkControllerClassID = "02"
)

func CollectVirtualFunctions(fs sysfs.FS) ([]ghw.PCIAddress, error) {
	pci, err := ghw.PCI()
	if err != nil {
		return nil, err
	}

	var addresses []ghw.PCIAddress
	for _, dev := range pci.Devices {
		if dev.Product.VendorID != mellanoxVendorID || dev.Class.ID != networkControllerClassID {
			continue
		}

		address := *ghw.PCIAddressFromString(dev.Address)
		sysFSDev, err := fs.PCIDevice(address)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("error looking up sysfs pci device %s: %w", &address, err)
			}
			continue
		}

		sriov, err := sysFSDev.SRIOV()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("error getting sriov for %s: %w", dev.Address, err)
			}
			continue
		}
		if sriov.NumVFs == 0 {
			continue
		}

		virtFns, err := sysFSDev.Virtfns()
		if err != nil {
			return nil, fmt.Errorf("error discovering virtual functions for %s: %w", dev.Address, err)
		}

		for _, virtFn := range virtFns {
			virtFnAddr, err := virtFn.Address()
			if err != nil {
				return nil, fmt.Errorf("error getting virtual function %s address: %w", virtFn, err)
			}

			addresses = append(addresses, *virtFnAddr)
		}
	}
	return addresses, nil
}

func CollectTAPFunctions(devices []string) ([]ghw.PCIAddress, error) {
	var addresses []ghw.PCIAddress

	// Fill the addresses array
	for _, device := range devices {
		addr := ghw.PCIAddress{
			Device: device,
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

func GenerateVirtualFunctions(pfDevice string, numVFs int, offset int) ([]ghw.PCIAddress, error) {
	var addresses []ghw.PCIAddress

	baseAddress := *ghw.PCIAddressFromString(pfDevice)

	baseDevice, err := strconv.Atoi(baseAddress.Device)
	if err != nil {
		return nil, fmt.Errorf("error parsing device number: %v", err)
	}
	baseFunction, err := strconv.Atoi(baseAddress.Function)
	if err != nil {
		return nil, fmt.Errorf("error parsing function number: %v", err)
	}

	for i := 0; i < numVFs; i++ {
		device := baseDevice
		function := baseFunction + offset + i

		if function > 0x7 {
			device += function / 0x8
			function %= 0x8
		}

		newAddressStr := fmt.Sprintf("%s:%s:%02x.%x", baseAddress.Domain, baseAddress.Bus, device, function)
		newAddress := *ghw.PCIAddressFromString(newAddressStr)
		addresses = append(addresses, newAddress)
	}

	return addresses, nil
}
