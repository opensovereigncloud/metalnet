// Copyright 2022 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"encoding/json"

	"inet.af/netaddr"
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

// IP is an IP address.
// +kubebuilder:validation:Type=string
type IP struct {
	netaddr.IP `json:"-"`
}

func (in *IP) DeepCopyInto(out *IP) {
	*out = *in
}

func (in *IP) DeepCopy() *IP {
	return &IP{in.IP}
}

func (i IP) GomegaString() string {
	return i.String()
}

func (i *IP) UnmarshalJSON(b []byte) error {
	if len(b) == 4 && string(b) == "null" {
		i.IP = netaddr.IP{}
		return nil
	}

	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	p, err := netaddr.ParseIP(str)
	if err != nil {
		return err
	}

	i.IP = p
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
	return i.IP.String()
}

func (i *IP) IsValid() bool {
	return i != nil && i.IP.IsValid()
}

func (i *IP) IsZero() bool {
	return i == nil || i.IP.IsZero()
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

func (_ IP) OpenAPISchemaType() []string { return []string{"string"} }

func (_ IP) OpenAPISchemaFormat() string { return "ip" }

func NewIP(ip netaddr.IP) IP {
	return IP{ip}
}

func ParseIP(s string) (IP, error) {
	addr, err := netaddr.ParseIP(s)
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
	return IP{netaddr.MustParseIP(s)}
}

func MustParseNewIP(s string) *IP {
	ip, err := ParseNewIP(s)
	utilruntime.Must(err)
	return ip
}

func NewIPPtr(ip netaddr.IP) *IP {
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
	netaddr.IPPrefix `json:"-"`
}

func (i IPPrefix) GomegaString() string {
	return i.String()
}

func (i IPPrefix) IP() IP {
	return IP{i.IPPrefix.IP()}
}

func (i *IPPrefix) UnmarshalJSON(b []byte) error {
	if len(b) == 4 && string(b) == "null" {
		i.IPPrefix = netaddr.IPPrefix{}
		return nil
	}

	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	p, err := netaddr.ParseIPPrefix(str)
	if err != nil {
		return err
	}

	i.IPPrefix = p
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
	return &IPPrefix{in.IPPrefix}
}

func (in *IPPrefix) IsValid() bool {
	return in != nil && in.IPPrefix.IsValid()
}

func (in *IPPrefix) IsZero() bool {
	return in == nil || in.IPPrefix.IsZero()
}

func (_ IPPrefix) OpenAPISchemaType() []string { return []string{"string"} }

func (_ IPPrefix) OpenAPISchemaFormat() string { return "ip-prefix" }

func NewIPPrefix(prefix netaddr.IPPrefix) *IPPrefix {
	return &IPPrefix{IPPrefix: prefix}
}

func ParseIPPrefix(s string) (IPPrefix, error) {
	prefix, err := netaddr.ParseIPPrefix(s)
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
	return IPPrefix{netaddr.MustParseIPPrefix(s)}
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
