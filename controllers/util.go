package controllers

import (
	"context"
	"fmt"
	"net/netip"

	mb "github.com/onmetal/metalbond"
)

const (
	ROUTEADD = iota
	ROUTEREMOVE
)

func prepareMbParameters(ctx context.Context, ip string, ulRoute string) (*mb.NextHop, *mb.Destination, error) {

	prefix, err := netip.ParsePrefix(ip)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert interface ip to prefix version, reson=%v", err)
	}

	var ipversion mb.IPVersion
	if prefix.Addr().Is4() {
		ipversion = mb.IPV4
	} else {
		ipversion = mb.IPV6
	}

	dest := mb.Destination{
		IPVersion: ipversion,
		Prefix:    prefix,
	}

	hopIP, err := netip.ParseAddr(ulRoute)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid nexthop address: %s - %v", ulRoute, err)
	}

	hop := mb.NextHop{
		TargetAddress: hopIP,
		TargetVNI:     0,
		NAT:           false,
	}

	return &hop, &dest, nil
}
