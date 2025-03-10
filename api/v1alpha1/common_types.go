// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// LocalUIDReference is a reference to another entity including its UID
type LocalUIDReference struct {
	// Name is the name of the referenced entity.
	Name string `json:"name"`
	// UID is the UID of the referenced entity.
	// +optional
	UID types.UID `json:"uid,omitempty"`
}

// LBPort consists of port and protocol
type LBPort struct {
	// +kubebuilder:validation:Required
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// LBPort consists of port and protocol
type NATDetails struct {
	// +kubebuilder:validation:Required
	IP *IP `json:"ip"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	EndPort int32 `json:"endPort"`
}

// IP is an IP address.
// +kubebuilder:validation:Type=string
type IP struct {
	netip.Addr `json:"-"`
}

// IPReservation defines an IP or prefix pair with overlay and underlay addresses
type IPReservation struct {
	// Overlay is the overlay network IP or prefix
	Overlay string `json:"overlay"`
	// Underlay is the underlay network IP or prefix
	Underlay string `json:"underlay"`
}

// ControllerStatus represents the status reported by a specific controller instance
type ControllerStatus struct {
	// ControllerID is the unique identifier of the controller instance
	// +required
	ControllerID string `json:"controllerID"`

	// State is the state reported by this controller
	// +optional
	State string `json:"state,omitempty"`

	// ObservedGeneration represents the .metadata.generation that the controller last processed
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is a list of conditions associated with this controller
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// LastUpdateTime is when the status was last updated by this controller
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`
}

// CommonStatus provides a shared status structure for multiple controllers
type CommonStatus struct {
	// ControllerStatuses contains status information from different controllers
	// +optional
	ControllerStatuses []ControllerStatus `json:"controllerStatuses,omitempty"`

	// Conditions is a list of conditions for the overall resource
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// State is the aggregated state of the resource
	// +required
	State string `json:"state,omitempty"`

	// LastUpdateTime is when the overall status was last updated
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`
}

// ConditionType defines standard condition types
type ConditionType string

const (
	// ConditionReady indicates the resource is ready for use
	ConditionReady ConditionType = "Ready"
)

// SetNetworkInterfaceControllerStatus sets or updates the status from a specific controller instance
func SetNetworkInterfaceControllerStatus(status *NetworkInterfaceStatus, controllerID string, state string, message string, generation int64, conditions ...metav1.Condition) {
	s := &status.CommonStatus

	// Find existing controller status or create a new one
	var controllerStatus *ControllerStatus
	for i := range s.ControllerStatuses {
		if s.ControllerStatuses[i].ControllerID == controllerID {
			controllerStatus = &s.ControllerStatuses[i]
			break
		}
	}

	if controllerStatus == nil {
		s.ControllerStatuses = append(s.ControllerStatuses, ControllerStatus{
			ControllerID: controllerID,
		})
		controllerStatus = &s.ControllerStatuses[len(s.ControllerStatuses)-1]
	}

	// Update controller status fields
	controllerStatus.State = state
	controllerStatus.Message = message
	controllerStatus.ObservedGeneration = generation
	now := metav1.Now()
	controllerStatus.LastUpdateTime = &now

	// Update the overall status last update time
	s.LastUpdateTime = &now

	// Set/update conditions
	for _, condition := range conditions {
		condition.LastTransitionTime = now
		// Update existing condition or add new one
		existingCondition := false
		for i, c := range controllerStatus.Conditions {
			if c.Type == condition.Type {
				controllerStatus.Conditions[i] = condition
				existingCondition = true
				break
			}
		}
		if !existingCondition {
			controllerStatus.Conditions = append(controllerStatus.Conditions, condition)
		}
	}

	// Compute overall status (assuming Ready state has priority)
	if s.State == "" || s.State == "Pending" {
		s.State = state
	} else if state == "Error" {
		s.State = "Error"
	}
}

// SetLoadBalancerControllerStatus sets or updates the status from a specific controller instance
func SetLoadBalancerControllerStatus(status *LoadBalancerStatus, controllerID string, state string, message string, generation int64, conditions ...metav1.Condition) {
	s := &status.CommonStatus

	// Find existing controller status or create a new one
	var controllerStatus *ControllerStatus
	for i := range s.ControllerStatuses {
		if s.ControllerStatuses[i].ControllerID == controllerID {
			controllerStatus = &s.ControllerStatuses[i]
			break
		}
	}

	if controllerStatus == nil {
		s.ControllerStatuses = append(s.ControllerStatuses, ControllerStatus{
			ControllerID: controllerID,
		})
		controllerStatus = &s.ControllerStatuses[len(s.ControllerStatuses)-1]
	}

	// Update controller status fields
	controllerStatus.State = state
	controllerStatus.Message = message
	controllerStatus.ObservedGeneration = generation
	now := metav1.Now()
	controllerStatus.LastUpdateTime = &now

	// Update the overall status last update time
	s.LastUpdateTime = &now

	// Set/update conditions
	for _, condition := range conditions {
		condition.LastTransitionTime = now
		// Update existing condition or add new one
		existingCondition := false
		for i, c := range controllerStatus.Conditions {
			if c.Type == condition.Type {
				controllerStatus.Conditions[i] = condition
				existingCondition = true
				break
			}
		}
		if !existingCondition {
			controllerStatus.Conditions = append(controllerStatus.Conditions, condition)
		}
	}

	// Compute overall status (assuming Ready state has priority)
	if s.State == "" || s.State == "Pending" {
		s.State = state
	} else if state == "Error" {
		s.State = "Error"
	}
}

// AggregateNetworkInterfaceStatus computes the overall status based on controller statuses
func AggregateNetworkInterfaceStatus(status *NetworkInterfaceStatus, readyNeeded int) {
	s := &status.CommonStatus

	// Track controller states
	readyCount := 0
	totalCount := 0
	hasError := false
	hasPending := false

	for _, cs := range s.ControllerStatuses {
		totalCount++

		if cs.State == "Error" {
			hasError = true
		} else if cs.State == "Pending" {
			hasPending = true
		} else if cs.State == "Ready" {
			readyCount++
		}
	}

	// Determine overall state based on controller statuses
	var stateStr string
	if hasError {
		stateStr = "Error"
	} else if hasPending {
		stateStr = "Pending"
	} else if readyCount >= readyNeeded {
		// At least 2 controllers are reporting Ready
		stateStr = "Ready"
	} else {
		// No controllers reporting yet or not enough Ready reports
		stateStr = "Pending"
	}

	// Update both CommonStatus.State and the type-specific State
	s.State = stateStr
	status.State = NetworkInterfaceState(stateStr)

	// Update the overall status timestamp
	now := metav1.Now()
	s.LastUpdateTime = &now
}

// NewCondition creates a new metav1.Condition
func NewCondition(conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

/*
Status Usage Example for HA Controllers:

// To report status from one controller instance:
func (r *Controller) updateStatus(ctx context.Context, obj *v1alpha1.NetworkInterface) error {
    // Generate a unique controller ID - typically includes the node name
    controllerID := fmt.Sprintf("metalnet-controller-%s-%s", r.NodeName, r.InstanceID)

    // Create a ready condition
    readyCondition := v1alpha1.NewCondition(
        string(v1alpha1.ConditionReady),
        metav1.ConditionTrue,
        "ResourceReady",
        "The resource has been successfully processed",
    )

    // Set the controller status with the unique controller ID
    v1alpha1.SetNetworkInterfaceControllerStatus(
        &obj.Status,                            // NetworkInterfaceStatus pointer
        controllerID,                           // controller ID - unique to this controller instance
        string(v1alpha1.NetworkInterfaceStateReady), // state - either Ready or Error
        "Resource successfully processed",      // message - detailed status message
        obj.Generation,                         // observed generation - tracks which version was processed
        readyCondition,                         // conditions
    )

    // Automatically compute the overall status based on all controller reports
    v1alpha1.AggregateNetworkInterfaceStatus(&obj.Status)

    // Update the resource
    return r.Status().Update(ctx, obj)
}

// A different controller instance reports its own status
func (r *Controller) updateStatusFromSecondInstance(ctx context.Context, obj *v1alpha1.NetworkInterface) error {
    // Different controller instance with a different ID
    controllerID := fmt.Sprintf("metalnet-controller-%s-%s", r.NodeName, r.InstanceID)

    // Create a ready condition
    readyCondition := v1alpha1.NewCondition(
        string(v1alpha1.ConditionReady),
        metav1.ConditionTrue,
        "ResourceReady",
        "The resource has been successfully processed",
    )

    // Set this controller's status
    v1alpha1.SetNetworkInterfaceControllerStatus(
        &obj.Status,                           // NetworkInterfaceStatus pointer
        controllerID,                          // controller ID - unique to this instance
        string(v1alpha1.NetworkInterfaceStateReady), // state - either Ready or Error
        "Resource successfully processed",     // message
        obj.Generation,                        // observed generation
        readyCondition,                        // conditions
    )

    // Compute overall status
    v1alpha1.AggregateNetworkInterfaceStatus(&obj.Status)

    // Update the resource
    return r.Status().Update(ctx, obj)
}

// When viewing the resource with kubectl get:
// NAME         STATUS   NODENAME   NETWORK     ...
// interface1   Ready    node1      network1    ...
// interface2   Pending  node2      network1    ...

// For detailed status, use kubectl describe to see individual controller statuses:
// ...
// Status:
//   Controller Statuses:
//     Controller ID: metalnet-controller-node1-abc123
//       State: Ready
//       Message: Resource successfully processed
//       Last Update: 2023-06-07T12:34:56Z
//     Controller ID: metalnet-controller-node2-def456
//       State: Ready
//       Message: Resource successfully processed
//       Last Update: 2023-06-07T12:35:01Z
//   State: Ready
//   ...

// To get status from a specific controller:
func getControllerStatus(obj *v1alpha1.NetworkInterface, controllerID string) (string, string, *metav1.Time) {
    for _, cs := range obj.Status.ControllerStatuses {
        if cs.ControllerID == controllerID {
            return cs.State, cs.Message, cs.LastUpdateTime
        }
    }
    return "Unknown", "Controller has not reported status", nil
}

// Check if all controllers are ready
func isResourceReady(obj *v1alpha1.NetworkInterface) bool {
    return obj.Status.State == string(v1alpha1.NetworkInterfaceStateReady)
}

// For LoadBalancer resources, use the LoadBalancer-specific functions instead:
// v1alpha1.SetLoadBalancerControllerStatus() and v1alpha1.AggregateLoadBalancerStatus()
*/

func (in *IP) DeepCopyInto(out *IP) {
	*out = *in
}

func (in *IP) DeepCopy() *IP {
	return &IP{in.Addr}
}

func (i IP) GomegaString() string {
	return i.String()
}

func (i *IP) UnmarshalJSON(b []byte) error {
	if len(b) == 4 && string(b) == "null" {
		i.Addr = netip.Addr{}
		return nil
	}

	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	p, err := netip.ParseAddr(str)
	if err != nil {
		return err
	}

	i.Addr = p
	return nil
}

func (i IP) MarshalJSON() ([]byte, error) {
	if i.IsZero() {
		// Encode unset/nil objects as JSON's "null".
		return []byte("null"), nil
	}
	return json.Marshal(i.String())
}

func (i IP) ToUnstructured() interface{} {
	if i.IsZero() {
		return nil
	}
	return i.String()
}

func (i *IP) IsValid() bool {
	return i != nil && i.Addr.IsValid()
}

func (i *IP) IsZero() bool {
	return i == nil || !i.Addr.IsValid()
}

func (i IP) Family() corev1.IPFamily {
	switch {
	case i.Is4():
		return corev1.IPv4Protocol
	case i.Is6():
		return corev1.IPv6Protocol
	default:
		return ""
	}
}

func (i IP) OpenAPISchemaType() []string { return []string{"string"} }

func (i IP) OpenAPISchemaFormat() string { return "ip" }

func NewIP(ip netip.Addr) IP {
	return IP{ip}
}

func ParseIP(s string) (IP, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return IP{}, err
	}
	return IP{addr}, nil
}

func ParseNewIP(s string) (*IP, error) {
	ip, err := ParseIP(s)
	if err != nil {
		return nil, err
	}
	return &ip, nil
}

func MustParseIP(s string) IP {
	return IP{netip.MustParseAddr(s)}
}

func MustParseNewIP(s string) *IP {
	ip, err := ParseNewIP(s)
	utilruntime.Must(err)
	return ip
}

func NewIPPtr(ip netip.Addr) *IP {
	return &IP{ip}
}

func PtrToIP(addr IP) *IP {
	return &addr
}

func EqualIPs(a, b IP) bool {
	return a == b
}

// IPPrefix represents a network prefix.
// +kubebuilder:validation:Type=string
// +nullable
type IPPrefix struct {
	netip.Prefix `json:"-"`
}

func (i IPPrefix) GomegaString() string {
	return i.String()
}

func (i IPPrefix) IP() IP {
	return IP{i.Addr()}
}

func (i *IPPrefix) UnmarshalJSON(b []byte) error {
	if len(b) == 4 && string(b) == "null" {
		i.Prefix = netip.Prefix{}
		return nil
	}

	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	p, err := netip.ParsePrefix(str)
	if err != nil {
		return err
	}

	i.Prefix = p
	return nil
}

func (i IPPrefix) MarshalJSON() ([]byte, error) {
	if i.IsZero() {
		// Encode unset/nil objects as JSON's "null".
		return []byte("null"), nil
	}
	return json.Marshal(i.String())
}

func (i IPPrefix) ToUnstructured() interface{} {
	if i.IsZero() {
		return nil
	}
	return i.String()
}

func (in *IPPrefix) DeepCopyInto(out *IPPrefix) {
	*out = *in
}

func (in *IPPrefix) DeepCopy() *IPPrefix {
	return &IPPrefix{in.Prefix}
}

func (in *IPPrefix) IsValid() bool {
	return in != nil && in.Prefix.IsValid()
}

func (in *IPPrefix) IsZero() bool {
	return in == nil || !in.Prefix.IsValid()
}

func (i IPPrefix) OpenAPISchemaType() []string { return []string{"string"} }

func (i IPPrefix) OpenAPISchemaFormat() string { return "ip-prefix" }

func NewIPPrefix(prefix netip.Prefix) *IPPrefix {
	return &IPPrefix{Prefix: prefix}
}

func ParseIPPrefix(s string) (IPPrefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return IPPrefix{}, err
	}
	return IPPrefix{prefix}, nil
}

func ParseNewIPPrefix(s string) (*IPPrefix, error) {
	prefix, err := ParseIPPrefix(s)
	if err != nil {
		return nil, err
	}
	return &prefix, nil
}

func MustParseIPPrefix(s string) IPPrefix {
	return IPPrefix{netip.MustParsePrefix(s)}
}

func MustParseNewIPPrefix(s string) *IPPrefix {
	prefix, err := ParseNewIPPrefix(s)
	utilruntime.Must(err)
	return prefix
}

func PtrToIPPrefix(prefix IPPrefix) *IPPrefix {
	return &prefix
}

func EqualIPPrefixes(a, b IPPrefix) bool {
	return a == b
}

// AggregateLoadBalancerStatus computes the overall status based on controller statuses
func AggregateLoadBalancerStatus(status *LoadBalancerStatus, readyNeeded int) {
	s := &status.CommonStatus

	// Track controller states
	readyCount := 0
	totalCount := 0
	hasError := false
	hasPending := false

	for _, cs := range s.ControllerStatuses {
		totalCount++

		if cs.State == "Error" {
			hasError = true
		} else if cs.State == "Pending" {
			hasPending = true
		} else if cs.State == "Ready" {
			readyCount++
		}
	}

	// Determine overall state based on controller statuses
	var stateStr string
	if hasError {
		stateStr = "Error"
	} else if hasPending { // Need at least 2 controllers reporting Ready
		stateStr = "Pending"
	} else if readyCount >= readyNeeded {
		// At least 2 controllers are reporting Ready
		stateStr = "Ready"
	} else {
		// No controllers reporting yet or not enough Ready reports
		stateStr = "Pending"
	}

	// Update both CommonStatus.State and the type-specific State
	s.State = stateStr
	status.State = LoadBalancerState(stateStr)

	// Update the overall status timestamp
	now := metav1.Now()
	s.LastUpdateTime = &now
}
