package health

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// Configuration variables that can be adjusted for testing
var (
	maxRetries = 10
	timeout    = 5 * time.Second
	// For testing only - allows test to inject custom dial function
	grpcDialFn func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
)

// StartGRPCHealthCheck connects to the gRPC service with backoff,
// then starts background health watching. It exits with code 1 if health check fails.
func StartGRPCHealthCheck(address string, logger logr.Logger) error {
	logger.Info("Starting health checker", "address", address)

	// Try initial connection with backoff
	var conn *grpc.ClientConn
	var err error

	backoff := 100 * time.Millisecond

	// Try to establish initial connection with backoff
	for i := 0; i < maxRetries; i++ {
		// Use custom dial function for tests if provided
		if grpcDialFn != nil {
			conn, err = grpcDialFn(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		} else {
			conn, err = grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}

		if err == nil {
			// Connection succeeded, verify health
			client := grpc_health_v1.NewHealthClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			resp, healthErr := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
			cancel()

			if healthErr == nil && resp.Status == grpc_health_v1.HealthCheckResponse_SERVING {
				// Health check succeeded
				logger.Info("Successfully connected and verified service health", "address", address, "status", resp.Status)
				break
			}

			// Health check failed, close connection and retry
			conn.Close()
			if healthErr != nil {
				logger.Error(healthErr, "Health check failed, retrying", "attempt", i+1)
				err = healthErr
			} else {
				err = fmt.Errorf("service not healthy: %v", resp.Status)
				logger.Error(err, "Service not healthy, retrying", "attempt", i+1)
			}
		} else {
			logger.Error(err, "Failed to connect, retrying", "attempt", i+1)
		}

		time.Sleep(backoff)
		backoff *= 2
	}

	if err != nil {
		return fmt.Errorf("failed to connect after %d attempts: %w", maxRetries, err)
	}

	// Start background monitoring - this will call os.Exit(1) if health check fails
	// In test mode, avoid os.Exit
	testMode := os.Getenv("HEALTH_TEST_MODE") == "1"

	go func() {
		defer conn.Close()
		client := grpc_health_v1.NewHealthClient(conn)

		// Simple Watch - no timeout or fancy stuff
		stream, err := client.Watch(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: ""})
		if err != nil {
			logger.Error(err, "Failed to watch health")
			if !testMode {
				os.Exit(1)
			}
			return
		}

		// Continuously check health
		for {
			resp, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled {
					logger.Info("Health check was canceled")
					return
				}
				logger.Error(err, "Error receiving health update")
				if !testMode {
					os.Exit(1)
				}
				return
			}

			if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				logger.Info("Service is unhealthy", "status", resp.Status)
				if !testMode {
					os.Exit(1)
				}
				return
			}
		}
	}()

	return nil
}
