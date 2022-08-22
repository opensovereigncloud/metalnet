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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkFunctionSpec defines the desired state of NetworkFunction
type NetworkFunctionSpec struct {
	NFType   string  `json:"type,omitempty"`
	NodeName *string `json:"nodeName,omitempty"`
	// TargetRef references the target for this NetworkFunction (currently only NetworkInterface).
	TargetRef *LocalUIDReference `json:"targetRef,omitempty"`
}

// NetworkFunctionStatus defines the observed state of NetworkFunction
type NetworkFunctionStatus struct {
	// Phase is the NetworkFunctionPhase of the VirtualIP.
	Phase                   NetworkFunctionPhase `json:"phase,omitempty"`
	LastPhaseTransitionTime *metav1.Time         `json:"phaseLastTransitionTime,omitempty"`
	PCIAddress              string               `json:"pciAddress,omitempty"`
}

// NetworkFunctionPhase is the binding phase of a NetworkFunction.
type NetworkFunctionPhase string

const (
	// NetworkFunctionUnbound is used for any NetworkFunction that is not bound.
	NetworkFunctionUnbound NetworkFunctionPhase = "Unbound"
	// NetworkFunctionPending is used for any NetworkFunction that is currently awaiting binding.
	NetworkFunctionPending NetworkFunctionPhase = "Pending"
	// NetworkFunctionBound is used for any NetworkFunction that is properly bound.
	NetworkFunctionBound NetworkFunctionPhase = "Bound"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// NetworkFunction is the Schema for the networkfunctions API
type NetworkFunction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkFunctionSpec   `json:"spec,omitempty"`
	Status NetworkFunctionStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkFunctionList contains a list of NetworkFunction
type NetworkFunctionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkFunction `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkFunction{}, &NetworkFunctionList{})
}
