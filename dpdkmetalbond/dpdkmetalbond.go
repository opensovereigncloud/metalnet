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
	"net"
	"net/netip"
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	mb "github.com/onmetal/metalbond"
	mbproto "github.com/onmetal/metalbond/pb"
	"github.com/onmetal/metalnet/dpdk"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
)

type MbInternalAccess interface {
	AddRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error
	RemoveRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error
	AddLoadBalancerServer(vni uint32, ip string, uid types.UID) error
	LoadBalancerServerExists(vni uint32, ip string) bool
	RemoveLoadBalancerServer(ip string, uid types.UID) error
	IsVniPeered(vni uint32) bool
	GetPeeredVnis() sets.Set[uint32]
	AddPeeredVni(peeredVNI uint32)
	RemovePeeredVni(peeredVNI uint32)
	SetPeeredPrefixes(peeredPrefixes map[uint32][]netip.Prefix)
	CleanupNotPeeredRoutes(ctx context.Context) error
}

type Client struct {
	log            *logrus.Entry
	dpdk           dpdk.Client
	config         ClientOptions
	lbServerMap    map[uint32]map[string]types.UID
	vni            uint32
	peeredVnis     sets.Set[uint32]
	peeredPrefixes map[uint32][]netip.Prefix
	mtxPeeredVnis  sync.RWMutex
}

type ClientOptions struct {
	IPv4Only         bool
	PreferredNetwork *net.IPNet
}

func NewClient(dpdkClient dpdk.Client, opts ClientOptions, vni uint32) (*Client, error) {
	return &Client{
		log:            logrus.WithFields(nil),
		dpdk:           dpdkClient,
		config:         opts,
		lbServerMap:    make(map[uint32]map[string]types.UID),
		vni:            vni,
		peeredVnis:     sets.New[uint32](),
		peeredPrefixes: make(map[uint32][]netip.Prefix),
	}, nil
}

func (c *Client) IsVniPeered(vni uint32) bool {
	c.mtxPeeredVnis.RLock()
	defer c.mtxPeeredVnis.RUnlock()

	if c.peeredVnis.Has(vni) {
		return true
	}

	return false
}

func (c *Client) GetPeeredVnis() sets.Set[uint32] {
	return c.peeredVnis
}

func (c *Client) AddPeeredVni(peeredVNI uint32) {
	c.log.Infof("Adding %d to peered VNI list", peeredVNI)
	c.mtxPeeredVnis.Lock()
	c.peeredVnis.Insert(peeredVNI)
	c.mtxPeeredVnis.Unlock()
	c.log.Infof("Added %d to peered VNI list", peeredVNI)
}

func (c *Client) RemovePeeredVni(peeredVNI uint32) {
	c.log.Infof("Removing %d from peered VNI list", peeredVNI)
	c.mtxPeeredVnis.Lock()
	c.peeredVnis.Delete(peeredVNI)
	c.mtxPeeredVnis.Unlock()
	c.log.Infof("Removed %d from peered VNI list", peeredVNI)
}

func (c *Client) AddLoadBalancerServer(vni uint32, ip string, uid types.UID) error {
	if _, exists := c.lbServerMap[vni]; !exists {
		c.lbServerMap[vni] = make(map[string]types.UID)
	}
	c.lbServerMap[vni][ip] = uid
	return nil
}

func (c *Client) LoadBalancerServerExists(vni uint32, ip string) bool {
	if _, exists := c.lbServerMap[vni]; !exists {
		return false
	}

	if _, exists := c.lbServerMap[vni][ip]; !exists {
		return false
	}

	return true
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

func (c *Client) addLocalRoute(vni, dstVni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	c.log.Infof("Adding local route for vni %d dstvni %d, dest %s, hop %s", vni, dstVni, dest, hop)
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

		if c.config.PreferredNetwork != nil {
			targetAddress := net.ParseIP(hop.TargetAddress.String())
			if !c.config.PreferredNetwork.Contains(targetAddress) {
				c.log.Infof("LB target %s is not in preferred network %s, ignoring...", targetAddress, c.config.PreferredNetwork)
				return nil
			}
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

	c.log.Infof("CreateRoute vni %d dstvni %d, dest %s, hop %s", vni, dstVni, dest, hop)
	if _, err := c.dpdk.CreateRoute(ctx, &dpdk.Route{
		RouteMetadata: dpdk.RouteMetadata{
			VNI: uint32(vni),
		},
		Spec: dpdk.RouteSpec{
			Prefix: dest.Prefix,
			NextHop: dpdk.RouteNextHop{
				VNI:     uint32(dstVni),
				Address: hop.TargetAddress,
			},
		},
	}); dpdk.IgnoreStatusErrorCode(err, dpdk.ROUTE_EXISTS) != nil {
		return fmt.Errorf("error creating route: %w", err)
	}
	return nil
}

func (c *Client) removeLocalRoute(vni, dstVni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
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
				VNI:     uint32(dstVni),
				Address: hop.TargetAddress,
			},
		},
	}); dpdk.IgnoreStatusErrorCode(err, dpdk.NO_VNI) != nil &&
		dpdk.IgnoreStatusErrorCode(err, dpdk.ROUTE_NOT_FOUND) != nil {
		return fmt.Errorf("error deleting route: %w", err)
	}
	return nil
}

func (c *Client) AddRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	c.log.Infof("AddRoute: vni=%d, dest=%s, hop=%s, peeredPrefixes=%v", vni, dest, hop, c.peeredPrefixes)
	dstVni := mb.VNI(c.vni)
	// the route belongs to the local VNI
	if dstVni == vni {
		if err := c.addLocalRoute(vni, vni, dest, hop); err != nil {
			return err
		}
	} else {
		// the route is belongs to a peered VNI and is of type standard
		if hop.Type == mbproto.NextHopType_STANDARD {
			// if we have set peered prefixes for this VNI, we need to check if the destination is in the list
			peeredPrefixes, exists := c.peeredPrefixes[uint32(vni)]
			// by default we add the route if no peered prefixes are set
			addRoute := true
			c.log.Infof("AddRoute peeredPrefixes %v", peeredPrefixes)
			if exists {
				// if the destination is not in the list of peered prefixes, we don't add the route
				addRoute = false
				for _, peeredPrefix := range peeredPrefixes {
					if peeredPrefix.Contains(dest.Prefix.Addr()) {
						addRoute = true
						break
					}
				}
			}

			c.log.Infof("AddRoute addRoute %v", addRoute)
			if addRoute {
				if err := c.addLocalRoute(dstVni, vni, dest, hop); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *Client) RemoveRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	c.log.Infof("RemoveRoute: vni=%d, dest=%s, hop=%s", vni, dest, hop)
	dstVni := mb.VNI(c.vni)
	// the route belongs to the local VNI
	if dstVni == vni {
		if err := c.removeLocalRoute(vni, vni, dest, hop); err != nil {
			return err
		}
	} else {
		// the route is belongs to a peered VNI and is of type standard
		if hop.Type == mbproto.NextHopType_STANDARD {
			if err := c.removeLocalRoute(dstVni, vni, dest, hop); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) SetPeeredPrefixes(peeredPrefixes map[uint32][]netip.Prefix) {
	c.log.Infof("SetPeeredPrefixes: %v for vni %d", peeredPrefixes, c.vni)
	c.peeredPrefixes = peeredPrefixes
}

func (c *Client) CleanupNotPeeredRoutes(ctx context.Context) error {
	c.log.Infof("CleanupNotPeeredRoutes for vni %d", c.vni)

	routes, err := c.dpdk.ListRoutes(ctx, c.vni)
	if err != nil {
		return fmt.Errorf("error listing dpdk routes for vni %d: %w", c.vni, err)
	}

	c.log.Infof("found %d routes for vni %d", len(routes), c.vni)
	// loop over all routes and delete the ones that are not peered
	for _, route := range routes {
		// only delete route if it is not the local vni and not peered
		if route.Spec.NextHop.VNI != c.vni && !c.peeredVnis.Has(route.Spec.NextHop.VNI) {
			c.log.Infof("deleting route %s from vni %d that is not longer peered", route.Spec.Prefix.String(), route.Spec.NextHop.VNI)
			if err := c.dpdk.DeleteRoute(ctx, &dpdk.Route{
				RouteMetadata: dpdk.RouteMetadata{
					VNI: c.vni,
				},
				Spec: dpdk.RouteSpec{
					Prefix: route.Spec.Prefix,
					NextHop: dpdk.RouteNextHop{
						VNI:     route.Spec.NextHop.VNI,
						Address: route.Spec.NextHop.Address,
					},
				},
			}); dpdk.IgnoreStatusErrorCode(err, dpdk.NO_VNI) != nil &&
				dpdk.IgnoreStatusErrorCode(err, dpdk.ROUTE_NOT_FOUND) != nil {
				return fmt.Errorf("error deleting route: %w", err)
			}
			c.log.Infof("deleted route %s from vni %d that was not longer peered", route.Spec.Prefix.String(), route.Spec.NextHop.VNI)
		}
	}

	return nil
}
