package control

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ironcore-dev/metalbond"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ReconcileControl manages skipping reconciliation and holds a reference
// to the Metalbond instance and related peer configuration.
type ReconcileControl struct {
	mu              sync.Mutex
	SkipReconcile   bool
	MBInstance      *metalbond.MetalBond // pointer to the Metalbond instance
	MetalbondPeers  []string             // list of peer addresses (from CLI)
	PendingRemovals *sync.Map            // pointer to the pending removals map
}

// SetSkip sets the skip flag.
func (rc *ReconcileControl) SetSkip(skip bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.SkipReconcile = skip
}

// ShouldSkip returns the skip flag value.
func (rc *ReconcileControl) ShouldSkip() bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.SkipReconcile
}

// StartControlWebserver starts the control web server for managing reconciliation
// and now provides endpoints for listing peers and flagging a peer for removal.
// The /remove endpoint will allow requests only if they originate from an IPv6
// address within the /64 CIDR derived from the NODE_IP environment variable.
func StartControlWebserver(control *ReconcileControl, bindAddr string) {
	// --- Security Setup: Compute the allowed /64 range from NODE_IP ---
	nodeIPStr := os.Getenv("NODE_IP")
	if nodeIPStr == "" {
		ctrl.Log.Error(fmt.Errorf("NODE_IP not set"), "Environment variable NODE_IP must be set")
		os.Exit(1)
	}

	nodeIP := net.ParseIP(nodeIPStr)
	if nodeIP == nil || nodeIP.To16() == nil {
		ctrl.Log.Error(fmt.Errorf("invalid NODE_IP"), "NODE_IP must be a valid IPv6 address")
		os.Exit(1)
	}

	// Construct the /64 network based on NODE_IP.
	// For example, if NODE_IP is "2001:db8::1", the allowed network will be "2001:db8::/64".
	_, allowedNet, err := net.ParseCIDR(fmt.Sprintf("%s/64", nodeIP.String()))
	if err != nil {
		ctrl.Log.Error(err, "failed to create /64 CIDR from NODE_IP")
		os.Exit(1)
	}
	ctrl.Log.Info("Allowed removal network", "allowedNet", allowedNet.String())

	// --- Existing endpoints ---
	http.HandleFunc("/skip", func(w http.ResponseWriter, r *http.Request) {
		control.SetSkip(true)
		ctrl.Log.Info("Received /skip request - reconciliation skipped.")
		_, _ = fmt.Fprintln(w, "Reconciliation skipped.")
	})

	http.HandleFunc("/resume", func(w http.ResponseWriter, r *http.Request) {
		control.SetSkip(false)
		ctrl.Log.Info("Received /resume request - reconciliation resumed.")
		_, _ = fmt.Fprintln(w, "Reconciliation resumed.")
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if control.ShouldSkip() {
			ctrl.Log.Info("Received /status request - reconciliation is currently skipped.")
			_, _ = fmt.Fprintln(w, "Reconciliation is currently skipped.")
		} else {
			ctrl.Log.Info("Received /status request - reconciliation is active.")
			_, _ = fmt.Fprintln(w, "Reconciliation is active.")
		}
	})

	// Endpoint to list Metalbond peers (unchanged).
	http.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		type PeerInfo struct {
			Address               string `json:"address"`
			State                 string `json:"state"`
			LastKeepaliveSent     string `json:"last_keepalive_sent,omitempty"`
			LastKeepaliveReceived string `json:"last_keepalive_received,omitempty"`
		}

		var infos []PeerInfo
		for _, peer := range control.MetalbondPeers {
			// Query the peer state.
			state, err := control.MBInstance.PeerState(peer)
			stateStr := ""
			if err != nil {
				stateStr = fmt.Sprintf("error: %v", err)
			} else {
				stateStr = fmt.Sprintf("%v", state)
			}

			// Optionally get keepalive timestamps.
			var sentStr, recvStr string
			if sent, err := control.MBInstance.PeerLastKeepaliveSent(peer); err == nil {
				sentStr = sent.Format(time.RFC3339)
			}
			if recv, err := control.MBInstance.PeerLastKeepaliveReceived(peer); err == nil {
				recvStr = recv.Format(time.RFC3339)
			}

			infos = append(infos, PeerInfo{
				Address:               peer,
				State:                 stateStr,
				LastKeepaliveSent:     sentStr,
				LastKeepaliveReceived: recvStr,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(infos); err != nil {
			http.Error(w, "failed to encode peer info", http.StatusInternalServerError)
		}
	})

	// --- Modified /remove endpoint ---
	// Instead of removing the peer immediately, we flag it in the pending removals map.
	// Additionally, only allow removal if the request originates from an allowed IPv6 /64 range.
	http.HandleFunc("/remove", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed; use POST", http.StatusMethodNotAllowed)
			return
		}

		// Security check: Extract the client's IP from the request and verify it belongs
		// to the allowed /64 range.
		remoteAddr := r.RemoteAddr
		remoteIPStr, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			http.Error(w, "invalid remote address", http.StatusInternalServerError)
			return
		}
		remoteIP := net.ParseIP(remoteIPStr)
		if remoteIP == nil {
			http.Error(w, "could not parse remote IP", http.StatusInternalServerError)
			return
		}
		if !allowedNet.Contains(remoteIP) {
			http.Error(w, "forbidden: request not from allowed IPv6 /64 range", http.StatusForbidden)
			return
		}

		// Process the removal request.
		peer := r.URL.Query().Get("peer")
		if peer == "" {
			http.Error(w, "Missing 'peer' parameter", http.StatusBadRequest)
			return
		}

		// Instead of directly calling RemovePeer here, flag the peer as pending removal.
		control.PendingRemovals.Store(peer, struct{}{})
		ctrl.Log.Info("Peer flagged for removal", "peer", peer)
		_, _ = fmt.Fprintf(w, "Peer %s flagged for removal. It will be removed automatically shortly.\n", peer)
	})

	ctrl.Log.Info("Control web server running", "address", bindAddr)
	if err := http.ListenAndServe(bindAddr, nil); err != nil {
		ctrl.Log.Error(err, "Failed to start control web server")
		os.Exit(1)
	}
}

// formatPodIP formats the pod IP for URL construction based on its IP version.
func formatPodIP(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid pod IP: %s", ip)
	}

	if parsedIP.To4() == nil && parsedIP.To16() != nil {
		// IPv6
		return fmt.Sprintf("[%s]", ip), nil
	}
	// IPv4 or other.
	return ip, nil
}

// exponentialBackoff calculates exponential backoff duration for each retry.
func exponentialBackoff(attempt int) time.Duration {
	return time.Duration(math.Pow(2, float64(attempt))) * time.Second
}

// SkipReconcileOnOtherPods queries for pods with a specific label and retries on failure with exponential backoff
func SkipReconcileOnOtherPods(nodeName, currentPodName, daemonSetName, namespace string) error {
	var err error

	for attempt := 0; attempt < 5; attempt++ {
		err = trySkipReconcile(nodeName, currentPodName, daemonSetName, namespace)
		if err == nil {
			return nil
		}

		ctrl.Log.Error(err, "Retrying SkipReconcileOnOtherPods", "attempt", attempt+1)
		time.Sleep(exponentialBackoff(attempt))
	}

	ctrl.Log.Error(err, "Failed after 3 retries")
	os.Exit(1)
	return err
}

// trySkipReconcile performs the actual pod listing and notifications
func trySkipReconcile(nodeName, currentPodName, daemonSetName, namespace string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("unable to create in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client: %w", err)
	}

	// Filter pods by node name and label 'app=metalnet'
	podList, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
		LabelSelector: "app=metalnet",
	})
	if err != nil {
		return fmt.Errorf("failed to list pods in namespace %q on node %q: %w", namespace, nodeName, err)
	}

	if len(podList.Items) == 0 {
		ctrl.Log.Info("No pods found with label app=metalnet")
		return nil
	}

	for _, pod := range podList.Items {
		if !strings.HasPrefix(pod.Name, daemonSetName) || pod.Name == currentPodName {
			continue
		}

		if pod.Status.PodIP == "" {
			ctrl.Log.Info("Pod has no IP assigned yet, skipping", "pod", pod.Name)
			continue
		}

		formattedIP, err := formatPodIP(pod.Status.PodIP)
		if err != nil {
			ctrl.Log.Error(err, "Failed to format pod IP", "pod", pod.Name, "ip", pod.Status.PodIP)
			continue
		}

		url := fmt.Sprintf("http://%s:8082/skip", formattedIP)
		resp, err := http.Get(url)
		if err != nil {
			ctrl.Log.Error(err, "Failed to notify pod to skip reconciliation",
				"pod", pod.Name, "ip", pod.Status.PodIP)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected response from pod: %s", resp.Status)
			ctrl.Log.Error(err, "Failed to notify pod", "pod", pod.Name, "ip", pod.Status.PodIP)
			_ = resp.Body.Close()
			return err
		}

		ctrl.Log.Info("Successfully notified pod to skip reconciliation",
			"pod", pod.Name, "ip", pod.Status.PodIP)
		_ = resp.Body.Close()
	}

	return nil
}
