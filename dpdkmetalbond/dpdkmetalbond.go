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

package dpdkmetalbond

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	mb "github.com/onmetal/metalbond"
	mbproto "github.com/onmetal/metalbond/pb"
	"github.com/onmetal/metalnet/dpdk"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

type MbInternalAccess interface {
	AddRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error
	RemoveRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error
	AddLoadBalancerServer(vni uint32, ip string, uid types.UID) error
	RemoveLoadBalancerServer(ip string, uid types.UID) error
	IsVniPeered(vni uint32) bool
	GetPeerVnis(vni uint32) (sets.Set[uint32], error)
	AddVniToPeerVnis(log logr.Logger, vni, peeredVNI uint32) error
	RemoveVniFromPeerVnis(log logr.Logger, vni, peeredVNI uint32) error
}

type Client struct {
	dpdk        dpdk.Client
	config      ClientOptions
	lbServerMap map[uint32]map[string]types.UID
	vniMap      map[uint32]sets.Set[uint32]
}

type ClientOptions struct {
	IPv4Only bool
}

func NewClient(dpdkClient dpdk.Client, opts ClientOptions) (*Client, error) {
	return &Client{
		dpdk:        dpdkClient,
		config:      opts,
		lbServerMap: make(map[uint32]map[string]types.UID),
		vniMap:      make(map[uint32]sets.Set[uint32]),
	}, nil
}

func (c *Client) IsVniPeered(vni uint32) bool {
	for _, peeredVnis := range c.vniMap {
		if peeredVnis.Has(vni) {
			return true
		}
	}
	return false
}

func (c *Client) GetPeerVnis(vni uint32) (sets.Set[uint32], error) {
	vnis, ok := c.vniMap[vni]
	if !ok {
		return sets.New[uint32](), nil
	}
	return vnis, nil
}

func (c *Client) AddVniToPeerVnis(log logr.Logger, vni, peeredVNI uint32) error {
	log.V(1).Info("Adding to peered VNI list", "VNI", vni, "peeredVNI", peeredVNI)
	set, ok := c.vniMap[vni]
	if !ok {
		set = sets.New[uint32]()
		c.vniMap[vni] = set
	}
	set.Insert(peeredVNI)
	log.V(1).Info("Added to peered VNI list", "VNI", vni, "peeredVNI", peeredVNI)
	return nil
}

func (c *Client) RemoveVniFromPeerVnis(log logr.Logger, vni, peeredVNI uint32) error {
	log.V(1).Info("Removing from peered VNI list", "VNI", vni, "peeredVNI", peeredVNI)
	set, ok := c.vniMap[vni]
	if !ok {
		return nil
	}
	set.Delete(peeredVNI)
	log.V(1).Info("Removed from peered VNI list", "VNI", vni, "peeredVNI", peeredVNI)
	return nil
}

func (c *Client) AddLoadBalancerServer(vni uint32, ip string, uid types.UID) error {
	if _, exists := c.lbServerMap[vni]; !exists {
		c.lbServerMap[vni] = make(map[string]types.UID)
	}
	c.lbServerMap[vni][ip] = uid
	return nil
}

func (c *Client) RemoveLoadBalancerServer(ip string, uid types.UID) error {
	for _, innerMap := range c.lbServerMap {
		for keyIp, value := range innerMap {
			if ip == keyIp && value == uid {
				delete(innerMap, ip)
			}
		}
	}
	return nil
}

func (c *Client) AddRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	ctx := context.TODO()

	if c.config.IPv4Only && dest.IPVersion != mb.IPV4 {
		// log.Infof("Received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
		return fmt.Errorf("received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
	}
	if hop.Type == mbproto.NextHopType_LOADBALANCER_TARGET {
		ip := dest.Prefix.Addr().String()
		_, ok := c.lbServerMap[uint32(vni)][ip]
		if !ok {
			return fmt.Errorf("no registered LoadBalancer on this client for vni %d and ip %s", vni, ip)
		}
		if _, err := c.dpdk.CreateLBTargetIP(ctx, &dpdk.LBTargetIP{
			LBTargetIPMetadata: dpdk.LBTargetIPMetadata{
				UID: c.lbServerMap[uint32(vni)][ip],
			},
			Spec: dpdk.LBTargetIPSpec{
				Address: hop.TargetAddress,
			},
		}); dpdk.IgnoreStatusErrorCode(err, dpdk.ALREADY_EXISTS) != nil {
			return fmt.Errorf("error creating lb target: %w", err)
		}
		return nil
	}

	if hop.Type == mbproto.NextHopType_NAT {
		if _, err := c.dpdk.CreateNATRoute(ctx, &dpdk.NATRoute{
			NATRouteMetadata: dpdk.NATRouteMetadata{
				VNI: uint32(vni),
			},
			Spec: dpdk.NATRouteSpec{
				Prefix: dest.Prefix,
				NextHop: dpdk.NATRouteNextHop{
					VNI:     uint32(vni),
					Address: hop.TargetAddress,
					MinPort: hop.NATPortRangeFrom,
					MaxPort: hop.NATPortRangeTo,
				},
			},
		}); dpdk.IgnoreStatusErrorCode(err, dpdk.ALREADY_EXISTS) != nil {
			return fmt.Errorf("error nat route: %w", err)
		}
		return nil
	}

	prefix := &dpdkproto.Prefix{
		PrefixLength: uint32(dest.Prefix.Bits()),
	}

	prefix.IpVersion = dpdkproto.IPVersion_IPv4 //only ipv4 in overlay is supported so far
	prefix.Address = []byte(dest.Prefix.Addr().String())

	if _, err := c.dpdk.CreateRoute(ctx, &dpdk.Route{
		RouteMetadata: dpdk.RouteMetadata{
			VNI: uint32(vni),
		},
		Spec: dpdk.RouteSpec{
			Prefix: dest.Prefix,
			NextHop: dpdk.RouteNextHop{
				VNI:     uint32(vni),
				Address: hop.TargetAddress,
			},
		},
	}); dpdk.IgnoreStatusErrorCode(err, dpdk.ROUTE_EXISTS) != nil {
		return fmt.Errorf("error creating route: %w", err)
	}
	return nil
}

func (c *Client) RemoveRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	ctx := context.TODO()

	if c.config.IPv4Only && dest.IPVersion != mb.IPV4 {
		// log.Infof("Received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
		return fmt.Errorf("received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
	}
	if hop.Type == mbproto.NextHopType_LOADBALANCER_TARGET {
		ip := dest.Prefix.Addr().String()
		_, ok := c.lbServerMap[uint32(vni)][ip]
		if !ok {
			return fmt.Errorf("no registered LoadBalancer on this client for vni %d and ip %s", vni, ip)
		}
		if err := c.dpdk.DeleteLBTargetIP(ctx, &dpdk.LBTargetIP{
			LBTargetIPMetadata: dpdk.LBTargetIPMetadata{
				UID: c.lbServerMap[uint32(vni)][ip],
			},
			Spec: dpdk.LBTargetIPSpec{
				Address: hop.TargetAddress,
			},
		}); dpdk.IgnoreStatusErrorCode(err, dpdk.NOT_FOUND) != nil &&
			dpdk.IgnoreStatusErrorCode(err, dpdk.NO_BACKIP) != nil &&
			dpdk.IgnoreStatusErrorCode(err, dpdk.NO_LB) != nil {
			return fmt.Errorf("error deleting lb target: %w", err)
		}
		return nil
	}

	if hop.Type == mbproto.NextHopType_NAT {
		if err := c.dpdk.DeleteNATRoute(ctx, &dpdk.NATRoute{
			NATRouteMetadata: dpdk.NATRouteMetadata{
				VNI: uint32(vni),
			},
			Spec: dpdk.NATRouteSpec{
				Prefix: dest.Prefix,
				NextHop: dpdk.NATRouteNextHop{
					VNI:     uint32(vni),
					Address: hop.TargetAddress,
					MinPort: hop.NATPortRangeFrom,
					MaxPort: hop.NATPortRangeTo,
				},
			},
		}); dpdk.IgnoreStatusErrorCode(err, dpdk.NOT_FOUND) != nil {
			return fmt.Errorf("error deleting nat route: %w", err)
		}
		return nil
	}

	if err := c.dpdk.DeleteRoute(ctx, &dpdk.Route{
		RouteMetadata: dpdk.RouteMetadata{
			VNI: uint32(vni),
		},
		Spec: dpdk.RouteSpec{
			Prefix: dest.Prefix,
			NextHop: dpdk.RouteNextHop{
				VNI:     uint32(vni),
				Address: hop.TargetAddress,
			},
		},
	}); dpdk.IgnoreStatusErrorCode(err, dpdk.NO_VNI) != nil &&
		dpdk.IgnoreStatusErrorCode(err, dpdk.ROUTE_NOT_FOUND) != nil {
		return fmt.Errorf("error deleting route: %w", err)
	}
	return nil
}
