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
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VirtualIPSpec defines the desired state of VirtualIP
type VirtualIPSpec struct {
	// Type is the type of VirtualIP.
	Type VirtualIPType `json:"type"`
	// IPFamily is the ip family of the VirtualIP.
	IPFamily corev1.IPFamily `json:"ipFamily"`
	// IP is the allocated IP
	IP *IP `json:"ip,omitempty"`
	// TargetRef references the target for this VirtualIP (currently only NetworkInterface).
	TargetRef *LocalUIDReference `json:"targetRef,omitempty"`
}

// VirtualIPType is a type of VirtualIP.
type VirtualIPType string

const (
	// VirtualIPTypePublic is a VirtualIP that allocates and routes a stable public IP.
	VirtualIPTypePublic VirtualIPType = "Public"
)

// VirtualIPStatus defines the observed state of VirtualIP
type VirtualIPStatus struct {
	// Phase is the VirtualIPPhase of the VirtualIP.
	Phase VirtualIPPhase `json:"phase,omitempty"`
	// LastPhaseTransitionTime is the last time the Phase transitioned from one value to another.
	LastPhaseTransitionTime *metav1.Time `json:"phaseLastTransitionTime,omitempty"`
	// TODO: we should establish a model how we can identify a VirtualIP standalone
	MachineID string `json:"machineID,omitempty"`
	// UnderlayIP of the host
	UnderlayIP *IP `json:"underlayIP,omitempty"`
}

// VirtualIPPhase is the binding phase of a VirtualIP.
type VirtualIPPhase string

const (
	// VirtualIPPhaseUnbound is used for any VirtualIP that is not bound.
	VirtualIPPhaseUnbound VirtualIPPhase = "Unbound"
	// VirtualIPPhasePending is used for any VirtualIP that is currently awaiting binding.
	VirtualIPPhasePending VirtualIPPhase = "Pending"
	// VirtualIPPhaseBound is used for any VirtualIP that is properly bound.
	VirtualIPPhaseBound VirtualIPPhase = "Bound"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VirtualIP is the Schema for the virtualips API
type VirtualIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of VirtualIP.
	Spec VirtualIPSpec `json:"spec,omitempty"`
	// Status defines the observed state of VirtualIP.
	Status VirtualIPStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VirtualIPList contains a list of VirtualIP
type VirtualIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is the list of VirtualIP.
	Items []VirtualIP `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualIP{}, &VirtualIPList{})
}
