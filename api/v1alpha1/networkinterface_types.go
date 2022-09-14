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
	// Virtual IP
	VIP *IP `json:"vip,omitempty"`
	// Prefix is the provided Prefix
	Prefix PrefixSource `json:"prefix,omitempty"`
	// NodeName is the name of the host machine on which the Interface should be created.
	NodeName *string `json:"nodeName,omitempty"`
}

// IPSource is the definition of how to obtain an IP.
type IPSource struct {
	// Value specifies an IP by using an IP literal.
	Value *IP `json:"value,omitempty"`
}

// PrefixSource is the source of the Prefix definition in an AliasPrefix
type PrefixSource struct {
	// Value is a single IPPrefix value as defined in the AliasPrefix
	Value *IPPrefix `json:"value,omitempty"`
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

// NetworkInterfaceStatus defines the observed state of NetworkInterface
type NetworkInterfaceStatus struct {
	// PCI Address details of this interface, Bus
	PCIBus string `json:"pcibus,omitempty"`

	// PCI Address details of this interface, Domain
	PCIDomain string `json:"pcidomain,omitempty"`

	// PCI Address details of this interface, Function
	PCIFunction string `json:"pcifunction,omitempty"`

	// PCI Address details of this interface, Slot
	PCISlot string `json:"pcislot,omitempty"`

	// DPDK PCI Address details of this interface
	PCIDpAddr string `json:"pcidpaddr,omitempty"`

	// Underlay IP of this interface
	UnderlayIP *IP `json:"underlayIP,omitempty"`

	// UID is the UID of NetworkInterface
	UID types.UID `json:"uid,omitempty"`

	// VirtualIP is any virtual ip assigned to the NetworkInterface.
	VirtualIP *IP `json:"virtualIP,omitempty"`

	// Prefix is the Prefix reserved for this NetworkInterface
	Prefix *IPPrefix `json:"prefix,omitempty"`

	// State is the NetworkInterfaceState of the NetworkInterface.
	State NetworkInterfaceState `json:"state,omitempty"` // READY, ERROR
}

// NetworkInterfaceState is the binding state of a NetworkInterface.
type NetworkInterfaceState string

const (
	// NetworkInterfaceStateReady is used for any NetworkInterface that is ready.
	NetworkInterfaceStateReady NetworkInterfaceState = "Ready"
	// NetworkInterfaceStateError is used for any NetworkInterface that is in intermediate state.
	NetworkInterfaceStatePending NetworkInterfaceState = "InProgress"
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
