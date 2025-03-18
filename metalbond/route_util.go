// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package metalbond

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/ironcore-dev/metalbond"
	"github.com/ironcore-dev/metalbond/pb"
)

type DefaultRouteOperation int

const (
	AddDefaultRoute DefaultRouteOperation = iota + 1
	RemoveDefaultRoute
)

type DefaultRouterAddress struct {
	RouterAddress    netip.Addr
	PublicVNI        uint32
	SetBySubsciption bool
	RWMutex          sync.RWMutex
}

type RouteUtil interface {
	AnnounceRoute(ctx context.Context, vni VNI, destination Destination, nextHop NextHop) error
	WithdrawRoute(ctx context.Context, vni VNI, destination Destination, nextHop NextHop) error
	Subscribe(ctx context.Context, vni VNI) error
	Unsubscribe(ctx context.Context, vni VNI) error
	IsSubscribed(ctx context.Context, vni VNI) bool
	GetRoutesForVni(ctx context.Context, vni VNI) error
	IsRouteAnnounced(ctx context.Context, vni VNI, dest Destination, targetAddress netip.Addr, targetType pb.NextHopType, natPortFrom, natPortTo uint16) bool
}

type MBRouteUtil struct {
	metalbond *metalbond.MetalBond
}

func NewMBRouteUtil(mb *metalbond.MetalBond) *MBRouteUtil {
	return &MBRouteUtil{mb}
}

type VNI = metalbond.VNI

func netIPAddrIPVersion(addr netip.Addr) metalbond.IPVersion {
	switch {
	case addr.Is4():
		return metalbond.IPV4
	case addr.Is6():
		return metalbond.IPV6
	default:
		fmt.Printf("unknown IP version for %s", addr)
		return 0
	}
}

type Destination struct {
	Prefix netip.Prefix
}

type NextHop struct {
	TargetAddress    netip.Addr
	TargetVNI        VNI
	TargetHopType    pb.NextHopType
	TargetNATMinPort uint16
	TargetNATMaxPort uint16
}

func (c *MBRouteUtil) AnnounceRoute(_ context.Context, vni VNI, destination Destination, nextHop NextHop) error {
	return c.metalbond.AnnounceRoute(vni, metalbond.Destination{
		IPVersion: netIPAddrIPVersion(destination.Prefix.Addr()),
		Prefix:    destination.Prefix,
	}, metalbond.NextHop{
		TargetAddress:    nextHop.TargetAddress,
		TargetVNI:        uint32(nextHop.TargetVNI),
		Type:             nextHop.TargetHopType,
		NATPortRangeFrom: nextHop.TargetNATMinPort,
		NATPortRangeTo:   nextHop.TargetNATMaxPort,
	})
}

func (c *MBRouteUtil) WithdrawRoute(_ context.Context, vni VNI, destination Destination, nextHop NextHop) error {
	return c.metalbond.WithdrawRoute(vni, metalbond.Destination{
		IPVersion: netIPAddrIPVersion(destination.Prefix.Addr()),
		Prefix:    destination.Prefix,
	}, metalbond.NextHop{
		TargetAddress:    nextHop.TargetAddress,
		TargetVNI:        uint32(nextHop.TargetVNI),
		Type:             nextHop.TargetHopType,
		NATPortRangeFrom: nextHop.TargetNATMinPort,
		NATPortRangeTo:   nextHop.TargetNATMaxPort,
	})
}

func (c *MBRouteUtil) Subscribe(_ context.Context, vni VNI) error {
	return c.metalbond.Subscribe(vni)
}

func (c *MBRouteUtil) Unsubscribe(_ context.Context, vni VNI) error {
	return c.metalbond.Unsubscribe(vni)
}

func (c *MBRouteUtil) IsSubscribed(_ context.Context, vni VNI) bool {
	return c.metalbond.IsSubscribed(vni)
}

func (c *MBRouteUtil) GetRoutesForVni(_ context.Context, vni VNI) error {
	return c.metalbond.GetRoutesForVni(vni)
}

func (c *MBRouteUtil) IsRouteAnnounced(_ context.Context, vni VNI, dest Destination, targetAddress netip.Addr, targetType pb.NextHopType, natPortFrom, natPortTo uint16) bool {
	mbDest := metalbond.Destination{
		Prefix: dest.Prefix,
	}

	mbNextHop := metalbond.NextHop{
		TargetAddress: targetAddress,
		TargetVNI:     uint32(vni),
		Type:          targetType,
	}

	if natPortTo > 0 {
		mbNextHop.NATPortRangeFrom = natPortFrom
		mbNextHop.NATPortRangeTo = natPortTo
	}
	return c.metalbond.IsRouteAnnounced(vni, mbDest, mbNextHop)
}
