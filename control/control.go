package control

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ReconcileControl manages skipping reconciliation
type ReconcileControl struct {
	mu            sync.Mutex
	SkipReconcile bool
}

// SetSkip sets the skip flag
func (rc *ReconcileControl) SetSkip(skip bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.SkipReconcile = skip
}

// ShouldSkip returns the skip flag value
func (rc *ReconcileControl) ShouldSkip() bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.SkipReconcile
}

// StartControlWebserver starts the control web server for managing reconciliation
func StartControlWebserver(control *ReconcileControl, bindAddr string) {
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

	ctrl.Log.Info("Control web server running", "address", bindAddr)
	if err := http.ListenAndServe(bindAddr, nil); err != nil {
		ctrl.Log.Error(err, "Failed to start control web server")
		os.Exit(1)
	}
}

// formatPodIP formats the pod IP for URL construction based on its IP version
func formatPodIP(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid pod IP: %s", ip)
	}

	if parsedIP.To4() == nil && parsedIP.To16() != nil {
		// IPv6
		return fmt.Sprintf("[%s]", ip), nil
	}
	// IPv4 or other
	return ip, nil
}

// exponentialBackoff calculates exponential backoff duration for each retry
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
