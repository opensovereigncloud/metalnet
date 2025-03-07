package ipv6manager_test

import (
	"os"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// TestMain is used to set up the Ginkgo test suite
func TestMain(m *testing.M) {
	// This will run the test suite in this package
	os.Exit(m.Run())
}

// SetupTestSuite sets up the Ginkgo test suite
func SetupTestSuite(t *testing.T) {
	// Configure Gomega
	gomega.RegisterFailHandler(ginkgo.Fail)

	// Run the tests
	ginkgo.RunSpecs(t, "IPv6Manager Suite")
}
