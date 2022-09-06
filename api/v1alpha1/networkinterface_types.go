/*
Copyright 2022 The Metal Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// NetworkInterfaceSpec defines the desired state of NetworkInterface
type NetworkInterfaceSpec struct {
	// NetworkRef is the Network this NetworkInterface is connected to
	NetworkRef corev1.LocalObjectReference `json:"networkRef"`
	// IPFamilies defines which IPFamilies this NetworkInterface is supporting
	IPFamilies []corev1.IPFamily `json:"ipFamilies"`
	// IP is the provided IP or EphemeralIP which should be assigned to this NetworkInterface
	// +optional
	IP *IP `json:"ip,omitempty"`
	// NodeName is the name of the host machine on which the VM should be scheduled.
	// If it is non-empty then scheduler simply schedules the VM on that host assuming it has enough resources.
	// +optional
	NodeName *string `json:"nodeName,omitempty"`
}

// IPSource is the definition of how to obtain an IP.
type IPSource struct {
	// Value specifies an IP by using an IP literal.
	Value *IP `json:"value,omitempty"`
}

// VirtualIPSource is the definition of how to obtain a VirtualIP.
type VirtualIPSource struct {
	// VirtualIPRef references a VirtualIP to use.
	VirtualIPRef *corev1.LocalObjectReference `json:"virtualIPRef,omitempty"`
}

// NetworkFunctionSource is the definition of how to obtain a network function.
type NetworkFunctionSource struct {
	// NetworkFunctionRef references a NetworkFunction to use.
	NetworkFunctionRef *corev1.LocalObjectReference `json:"networkFuncionRef,omitempty"`
}

// NetworkInterfaceAccess is the definition of how to ....
type NetworkInterfaceAccess struct {
	// UID is the UID of network object
	UID               types.UID         `json:"uid"`
	NetworkAttributes map[string]string `json:"networkAttributes,omitempty"`
}

// NetworkInterfaceStatus defines the observed state of NetworkInterface
type NetworkInterfaceStatus struct {
	// IPs represent the effective IP addresses of the NetworkInterface
	IPs []IP `json:"ips,omitempty"`
	// VirtualIP is any virtual ip assigned to the NetworkInterface.
	VirtualIP *IP `json:"virtualIP,omitempty"`

	// Access
	Access *NetworkInterfaceAccess `json:"access,omitempty"`

	// State is the NetworkInterfacePhase of the NetworkInterface.
	State NetworkInterfaceState `json:"state,omitempty"` // READY, ERROR

	// Phase is the NetworkInterfacePhase of the NetworkInterface.
	Phase NetworkInterfacePhase `json:"phase,omitempty"`
	// LastPhaseTransitionTime is the last time the Phase transitioned from one value to another.
	LastPhaseTransitionTime *metav1.Time `json:"phaseLastTransitionTime,omitempty"`
}

// NetworkInterfacePhase is the binding phase of a NetworkInterface.
type NetworkInterfacePhase string

const (
	// NetworkInterfacePhaseUnbound is used for any NetworkInterface that is not bound.
	NetworkInterfacePhaseUnbound NetworkInterfacePhase = "Unbound"
	// NetworkInterfacePhasePending is used for any NetworkInterface that is currently awaiting binding.
	NetworkInterfacePhasePending NetworkInterfacePhase = "Pending"
	// NetworkInterfacePhaseBound is used for any NetworkInterface that is properly bound.
	NetworkInterfacePhaseBound NetworkInterfacePhase = "Bound"
)

// NetworkInterfaceState is the binding state of a NetworkInterface.
type NetworkInterfaceState string

const (
	// NetworkInterfaceStateReady is used for any NetworkInterface that is ready.
	NetworkInterfaceStateReady NetworkInterfaceState = "Ready"
	// NetworkInterfaceStateError is used for any NetworkInterface that is some error occurred.
	NetworkInterfaceStateError NetworkInterfaceState = "Error"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ni
// +kubebuilder:printcolumn:name="Status",type=string,description="Current status of the network interface.",JSONPath=`.status.phase`,priority=0
// +kubebuilder:printcolumn:name="Host",type=string,description="Current baremetal host of the Network Interface.",JSONPath=`.spec.nodeName`,priority=0

// NetworkInterface is the Schema for the networkinterfaces API
type NetworkInterface struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of NetworkInterface.
	Spec NetworkInterfaceSpec `json:"spec,omitempty"`
	// Status defines the observed state of NetworkInterface.
	Status NetworkInterfaceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkInterfaceList contains a list of NetworkInterface
type NetworkInterfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of NetworkInterface.
	Items []NetworkInterface `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkInterface{}, &NetworkInterfaceList{})
}
