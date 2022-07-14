package v1alpha1

import (
	"encoding/json"

	"inet.af/netaddr"
)

// IP is an IP address.
//+kubebuilder:validation:Type=string
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
