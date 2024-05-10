// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetworkSpec defines the desired state of Network
type NetworkSpec struct {
	// +kubebuilder:validation:Maximum=16777215
	// +kubebuilder:validation:Minimum=1
	// ID is the unique identifier of the Network
	ID int32 `json:"id"`

	// PeeredIDs are the IDs of networks to peer with.
	PeeredIDs []int32 `json:"peeredIDs,omitempty"`

	// PeeredPrefixes are the allowed CIDRs of the peered networks.
	// +optional
	// +patchMergeKey=id
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=id
	PeeredPrefixes []PeeredPrefix `json:"peeredPrefixes,omitempty" patchStrategy:"merge" patchMergeKey:"peeredPrefixes"`

	// InternetGateway is a flag that indicates whether the network has an internet gateway.
	InternetGateway bool `json:"internetGateway,omitempty"`
}

// PeeredPrefix contains information of the peered networks and their allowed CIDRs.
type PeeredPrefix struct {
	// +kubebuilder:validation:Maximum=16777215
	// +kubebuilder:validation:Minimum=1
	ID       int32      `json:"id"`
	Prefixes []IPPrefix `json:"prefixes"`
}

type NetworkStatus struct {
	// Peerings contains the states of the network peerings for the network.
	Peerings []NetworkPeeringStatus `json:"peerings,omitempty"`
}

// NetworkPeeringState is the state a NetworkPeering
type NetworkPeeringState string

const (
	// NetworkPeeringStateError signals that the there was an error during network peering.
	NetworkPeeringStateError NetworkPeeringState = "Error"
	// NetworkPeeringStatePending signals that the network peering is not applied.
	NetworkPeeringStatePending NetworkPeeringState = "Pending"
	// NetworkPeeringStateReady signals that the network peering is ready.
	NetworkPeeringStateReady NetworkPeeringState = "Ready"
)

// NetworkPeeringStatus is the status of a network peering.
type NetworkPeeringStatus struct {
	// +kubebuilder:validation:Maximum=16777215
	// +kubebuilder:validation:Minimum=1
	// ID is the ID of the peered network.
	ID int32 `json:"id"`
	// State represents the network peering state
	State NetworkPeeringState `json:"state,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Handle",type=integer,description="ID of the network.",JSONPath=`.spec.id`,priority=10
// +kubebuilder:printcolumn:name="Age",type=date,description="Age of the network.",JSONPath=`.metadata.creationTimestamp`,priority=0

// Network is the Schema for the networks API
type Network struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec NetworkSpec `json:"spec"`

	Status NetworkStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkList contains a list of Network
type NetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Network `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Network{}, &NetworkList{})
}
