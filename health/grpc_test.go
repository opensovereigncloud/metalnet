package health

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	ctrl "sigs.k8s.io/controller-runtime"
)

const bufSize = 1024 * 1024

var _ = Describe("GRPC Health Check", func() {
	var (
		origMaxRetries int
		origTimeout    time.Duration
		origTestMode   string
		logger         = ctrl.Log.WithName("test")
	)

	BeforeEach(func() {
		// Save original values
		origMaxRetries = maxRetries
		origTimeout = timeout
		origTestMode = os.Getenv("HEALTH_TEST_MODE")
		os.Setenv("HEALTH_TEST_MODE", "1")
	})

	AfterEach(func() {
		// Restore original values
		maxRetries = origMaxRetries
		timeout = origTimeout
		os.Setenv("HEALTH_TEST_MODE", origTestMode)
	})

	Describe("Connection behavior", func() {
		Context("with an invalid host", func() {
			BeforeEach(func() {
				maxRetries = 2 // Make tests faster
			})

			It("should fail to connect", func() {
				err := StartGRPCHealthCheck("invalid-host:12345", logger)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to connect after 2 attempts"))
			})
		})

		Context("with an unhealthy server", func() {
			var (
				server       *grpc.Server
				healthServer *unhealthyServer
				lis          net.Listener
				addr         string
			)

			BeforeEach(func() {
				var err error
				lis, err = net.Listen("tcp", "127.0.0.1:0")
				Expect(err).NotTo(HaveOccurred())

				addr = lis.Addr().String()
				GinkgoWriter.Printf("Listening on %s\n", addr)

				server = grpc.NewServer()
				healthServer = &unhealthyServer{}
				grpc_health_v1.RegisterHealthServer(server, healthServer)

				go func() {
					_ = server.Serve(lis)
				}()

				maxRetries = 2 // Make tests faster
				// Wait for server to start
				time.Sleep(100 * time.Millisecond)
			})

			AfterEach(func() {
				server.Stop()
			})

			It("should detect an unhealthy server", func() {
				err := StartGRPCHealthCheck(addr, logger)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("NOT_SERVING"))
			})
		})

		Context("with a healthy server", func() {
			var (
				server       *grpc.Server
				healthServer *healthyServer
				lis          net.Listener
				addr         string
			)

			BeforeEach(func() {
				var err error
				lis, err = net.Listen("tcp", "127.0.0.1:0")
				Expect(err).NotTo(HaveOccurred())

				addr = lis.Addr().String()
				GinkgoWriter.Printf("Listening on %s\n", addr)

				server = grpc.NewServer()
				healthServer = &healthyServer{}
				grpc_health_v1.RegisterHealthServer(server, healthServer)

				go func() {
					_ = server.Serve(lis)
				}()

				// Wait for server to start
				time.Sleep(100 * time.Millisecond)
			})

			AfterEach(func() {
				server.Stop()
			})

			It("should connect and monitor successfully", func() {
				err := StartGRPCHealthCheck(addr, logger)
				Expect(err).NotTo(HaveOccurred())

				// Wait a bit to ensure monitoring is working
				time.Sleep(200 * time.Millisecond)
			})
		})
	})

	Describe("Multiple connection attempts", func() {
		Context("with initial failures before success", func() {
			var (
				server           *grpc.Server
				mockServer       *mockHealthServer
				listener         *bufconn.Listener
				completionChan   chan struct{}
				failureCount     int
				wantSuccessCount int
			)

			BeforeEach(func() {
				maxRetries = 5
				timeout = 100 * time.Millisecond

				failureCount = 3     // Will fail 3 times before succeeding
				wantSuccessCount = 5 // Want 5 successful background health checks

				completionChan = make(chan struct{})
				mockServer = &mockHealthServer{
					remainingFails:       failureCount,
					failCount:            failureCount,
					wantServingSuccesses: wantSuccessCount,
					notifyCompletion:     completionChan,
				}

				// Create a buffer for connection
				listener = bufconn.Listen(bufSize)

				// Create gRPC server
				server = grpc.NewServer()
				grpc_health_v1.RegisterHealthServer(server, mockServer)

				// Start the server in a goroutine
				go func() {
					_ = server.Serve(listener)
				}()

				// Create a bufconn dialer
				dialer := func(context.Context, string) (net.Conn, error) {
					return listener.Dial()
				}

				// Setup a custom dialer for testing
				grpcNewClient := func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
					return grpc.DialContext(context.Background(), "bufconn", append(opts, grpc.WithContextDialer(dialer))...)
				}

				// Add our test function to package scope
				grpcDialFn = grpcNewClient
			})

			AfterEach(func() {
				grpcDialFn = nil
				server.Stop()
			})

			It("should retry failed connections and succeed, then complete background checks", func() {
				err := StartGRPCHealthCheck("bufconn", logger)
				Expect(err).NotTo(HaveOccurred())

				// Wait for the background check to complete expected successes
				Eventually(completionChan, 5*time.Second).Should(BeClosed())

				// Verify counts
				mockServer.mu.Lock()
				defer mockServer.mu.Unlock()
				Expect(mockServer.failCount).To(Equal(failureCount))
				Expect(mockServer.remainingFails).To(Equal(0))
				Expect(mockServer.servingSuccesses).To(Equal(wantSuccessCount))
			})
		})
	})
})

// Test server implementations

// unhealthyServer always reports NOT_SERVING
type unhealthyServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (s *unhealthyServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
	}, nil
}

func (s *unhealthyServer) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	return stream.Send(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
	})
}

// healthyServer always reports SERVING
type healthyServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (s *healthyServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

func (s *healthyServer) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	return stream.Send(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	})
}

// mockHealthServer implements the gRPC health service with configurable failures
type mockHealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	mu                   sync.Mutex
	failCount            int
	remainingFails       int
	servingCount         int
	wantServingSuccesses int
	servingSuccesses     int
	notifyCompletion     chan struct{}
}

func (s *mockHealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.remainingFails > 0 {
		s.remainingFails--
		return nil, fmt.Errorf("mock service unavailable, %d failures remaining", s.remainingFails)
	}

	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

func (s *mockHealthServer) Watch(req *grpc_health_v1.HealthCheckRequest, server grpc_health_v1.Health_WatchServer) error {
	// Track success counts with a ticker to simulate background checks
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for i := 0; i < s.wantServingSuccesses; i++ {
		<-ticker.C

		// Send a serving status
		err := server.Send(&grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVING,
		})
		if err != nil {
			return err
		}

		s.mu.Lock()
		s.servingSuccesses++
		completed := s.servingSuccesses >= s.wantServingSuccesses
		if completed && s.notifyCompletion != nil {
			close(s.notifyCompletion)
			s.notifyCompletion = nil
		}
		s.mu.Unlock()
	}

	// Keep connection open
	<-context.Background().Done()
	return nil
}

func TestGRPCHealthCheck(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GRPC Health Check Suite")
}
