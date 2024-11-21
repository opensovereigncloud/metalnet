// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package metalbond

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/go-logr/logr"
	mb "github.com/ironcore-dev/metalbond"
	mbproto "github.com/ironcore-dev/metalbond/pb"
	"github.com/ironcore-dev/metalnet/internal"
	dpdk "github.com/onmetal/net-dpservice-go/api"
	dpdkclient "github.com/onmetal/net-dpservice-go/client"
	dpdkerrors "github.com/onmetal/net-dpservice-go/errors"
)

type ClientOptions struct {
	IPv4Only         bool
	PreferredNetwork *net.IPNet
}

type MetalnetClient struct {
	dpdk                 dpdkclient.Client
	config               ClientOptions
	metalnetCache        *internal.MetalnetCache
	mbInstance           *mb.MetalBond
	DefaultRouterAddress *DefaultRouterAddress

	log *logr.Logger
}

func NewMetalnetClient(log *logr.Logger, dpdkClient dpdkclient.Client, metalnetCache *internal.MetalnetCache, routerAddr *DefaultRouterAddress, opts ClientOptions) *MetalnetClient {
	return &MetalnetClient{
		dpdk:                 dpdkClient,
		metalnetCache:        metalnetCache,
		DefaultRouterAddress: routerAddr,
		config:               opts,
		log:                  log,
	}
}

func (c *MetalnetClient) SetMetalBond(mb *mb.MetalBond) {
	c.mbInstance = mb
}

func (c *MetalnetClient) addLocalRoute(destVni mb.VNI, vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	ctx := context.Background()

	if c.config.IPv4Only && dest.IPVersion != mb.IPV4 {
		// log.Infof("Received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
		return fmt.Errorf("received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
	}

	if hop.Type == mbproto.NextHopType_LOADBALANCER_TARGET {
		ip := dest.Prefix.Addr().String()
		uid, ok := c.metalnetCache.GetLoadBalancerServer(uint32(vni), ip)
		if !ok {
			return fmt.Errorf("no registered LoadBalancer on this client for vni %d and ip %s", vni, ip)
		}

		if c.config.PreferredNetwork != nil {
			targetAddress := net.ParseIP(hop.TargetAddress.String())
			if !c.config.PreferredNetwork.Contains(targetAddress) {
				c.log.V(1).Info(fmt.Sprintf("LB target %s is not in preferred network %s, ignoring...", targetAddress, c.config.PreferredNetwork))
				return nil
			}
		}

		if _, err := c.dpdk.CreateLoadBalancerTarget(ctx, &dpdk.LoadBalancerTarget{
			LoadBalancerTargetMeta: dpdk.LoadBalancerTargetMeta{
				LoadbalancerID: string(uid),
			},
			Spec: dpdk.LoadBalancerTargetSpec{
				TargetIP: &hop.TargetAddress,
			},
		}, dpdkerrors.Ignore(dpdkerrors.ALREADY_EXISTS),
		); err != nil {
			return fmt.Errorf("error creating lb target: %w", err)
		}
		return nil
	}

	if hop.Type == mbproto.NextHopType_NAT {
		natIP := dest.Prefix.Addr()
		if _, err := c.dpdk.CreateNeighborNat(ctx, &dpdk.NeighborNat{
			NeighborNatMeta: dpdk.NeighborNatMeta{
				NatIP: &natIP,
			},
			Spec: dpdk.NeighborNatSpec{
				Vni:           uint32(vni),
				MinPort:       uint32(hop.NATPortRangeFrom),
				MaxPort:       uint32(hop.NATPortRangeTo),
				UnderlayRoute: &hop.TargetAddress,
			},
		}, dpdkerrors.Ignore(dpdkerrors.ALREADY_EXISTS),
		); err != nil {
			return fmt.Errorf("error nat route: %w", err)
		}
		return nil
	}

	if _, err := c.dpdk.CreateRoute(ctx, &dpdk.Route{
		RouteMeta: dpdk.RouteMeta{
			VNI: uint32(vni),
		},
		Spec: dpdk.RouteSpec{
			Prefix: &dest.Prefix,
			NextHop: &dpdk.RouteNextHop{
				VNI: uint32(destVni),
				IP:  &hop.TargetAddress,
			},
		},
	}); err != nil {
		if dpdkerrors.IsStatusErrorCode(err, dpdkerrors.ROUTE_EXISTS) {
			routes, err := c.dpdk.ListRoutes(ctx, uint32(vni))
			if err != nil {
				// trigger reconcile
				defer func(mbInstance *mb.MetalBond, vni mb.VNI) {
					_ = mbInstance.GetRoutesForVni(vni)
				}(c.mbInstance, vni)
				return fmt.Errorf("error listing dpdk routes for vni %d: %w", vni, err)
			}

			for _, route := range routes.Items {
				// Look for an existing route with the same prefix as the destination
				if route.Spec.Prefix.Addr() == dest.Prefix.Addr() && route.Spec.Prefix.Bits() == dest.Prefix.Bits() {
					// Get the list of next hops for the given VNI and destination
					hops := c.mbInstance.GetNextHopForVniAndDestination(vni, dest)

					// Check if the next hop of the route is different from the target address
					if route.Spec.NextHop.IP.String() != hop.TargetAddress.String() {
						isRouteHopKnown := false

						// If there are more than 1 hops, verify if the next hop is already known
						if len(hops) > 1 {
							for _, knownHop := range hops {
								// Mark the next hop as known if it matches the route's next hop IP
								if route.Spec.NextHop.IP.String() == knownHop.TargetAddress.String() {
									isRouteHopKnown = true
									// Log that the prefix with the next hop is known
									c.log.Info(fmt.Sprintf("Prefix %s with nextHop %s and vni %d is known", dest.String(), route.Spec.NextHop.IP.String(), int(vni)))
									break
								}
							}
						}

						// If the next hop is not known, perform necessary actions
						if !isRouteHopKnown {
							c.log.Info(fmt.Sprintf("Prefix %s with nextHop %s and vni %d is unknown", dest.String(), route.Spec.NextHop.IP.String(), int(vni)))

							// Try to delete the existing route
							if _, err := c.dpdk.DeleteRoute(
								ctx,
								uint32(vni),
								&dest.Prefix,
								dpdkerrors.Ignore(dpdkerrors.NO_VNI, dpdkerrors.ROUTE_NOT_FOUND, dpdkerrors.ROUTE_BAD_PORT),
							); err != nil {
								// Trigger a reconciliation if there's an error
								defer func(mbInstance *mb.MetalBond, vni mb.VNI) {
									_ = mbInstance.GetRoutesForVni(vni)
								}(c.mbInstance, vni)
								return fmt.Errorf("error deleting existing route vni: %d, prefix: %s, nh: %s:  %w", vni, dest.Prefix.String(), hop.TargetAddress.String(), err)
							}

							// Try to create a new route with the updated next hop
							if _, err = c.dpdk.CreateRoute(ctx, &dpdk.Route{
								RouteMeta: dpdk.RouteMeta{
									VNI: uint32(vni),
								},
								Spec: dpdk.RouteSpec{
									Prefix: &dest.Prefix,
									NextHop: &dpdk.RouteNextHop{
										VNI: uint32(destVni),
										IP:  &hop.TargetAddress,
									},
								},
							}, dpdkerrors.Ignore(dpdkerrors.NO_VNI)); err != nil {
								// Trigger a reconciliation if there's an error
								defer func(mbInstance *mb.MetalBond, vni mb.VNI) {
									_ = mbInstance.GetRoutesForVni(vni)
								}(c.mbInstance, vni)
								return fmt.Errorf("error recreating route vni: %d, prefix: %s, nh: %s:  %w", vni, dest.Prefix.String(), hop.TargetAddress.String(), err)
							}
						}
					}
				}
			}
		} else {
			return fmt.Errorf("error creating route vni: %d, prefix: %s, nh: %s:  %w", vni, dest.Prefix.String(), hop.TargetAddress.String(), err)
		}
	}
	return nil
}

func (c *MetalnetClient) removeLocalRoute(destVni mb.VNI, vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	ctx := context.Background()

	if c.config.IPv4Only && dest.IPVersion != mb.IPV4 {
		// log.Infof("Received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
		return fmt.Errorf("received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
	}

	if hop.Type == mbproto.NextHopType_LOADBALANCER_TARGET {
		ip := dest.Prefix.Addr().String()
		uid, ok := c.metalnetCache.GetLoadBalancerServer(uint32(vni), ip)
		if !ok {
			return fmt.Errorf("no registered LoadBalancer on this client for vni %d and ip %s", vni, ip)
		}
		if _, err := c.dpdk.DeleteLoadBalancerTarget(
			ctx,
			string(uid),
			&hop.TargetAddress,
			dpdkerrors.Ignore(dpdkerrors.NOT_FOUND, dpdkerrors.NO_BACKIP, dpdkerrors.NO_LB),
		); err != nil {
			return fmt.Errorf("error deleting lb target: %w", err)
		}
		return nil
	}

	if hop.Type == mbproto.NextHopType_NAT {
		natIP := dest.Prefix.Addr()
		if _, err := c.dpdk.DeleteNeighborNat(ctx, &dpdk.NeighborNat{
			NeighborNatMeta: dpdk.NeighborNatMeta{
				NatIP: &natIP,
			},
			Spec: dpdk.NeighborNatSpec{
				Vni:           uint32(vni),
				MinPort:       uint32(hop.NATPortRangeFrom),
				MaxPort:       uint32(hop.NATPortRangeTo),
				UnderlayRoute: &hop.TargetAddress,
			},
		}, dpdkerrors.Ignore(dpdkerrors.NOT_FOUND),
		); err != nil {
			return fmt.Errorf("error deleting nat route: %w", err)
		}
		return nil
	}

	if _, err := c.dpdk.DeleteRoute(
		ctx,
		uint32(vni),
		&dest.Prefix,
		dpdkerrors.Ignore(dpdkerrors.NO_VNI, dpdkerrors.ROUTE_NOT_FOUND, dpdkerrors.ROUTE_BAD_PORT),
	); err != nil {
		return fmt.Errorf("error deleting route: %w", err)
	}
	return nil
}

func (c *MetalnetClient) AddRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	c.log.V(1).Info("AddRoute", "VNI", vni, "dest", dest, "hop", hop)
	var errStrs []string

	isDefaultRoute, err := c.FilterDefaultRoute(AddDefaultRoute, vni, dest, hop)
	if err != nil {
		return fmt.Errorf("error handling default router change: %w", err)
	} else if isDefaultRoute {
		return nil
	}

	if err := c.addLocalRoute(vni, vni, dest, hop); err != nil {
		errStrs = append(errStrs, err.Error())
	}

	if hop.Type == mbproto.NextHopType_STANDARD {
		// the ok flag is ignored because an empty set is returned if the VNI doesn't exist, and the loop below is skipped
		mbPeerVnis, _ := c.metalnetCache.GetPeerVnis(uint32(vni))
		peeredPrefixes, ok := c.metalnetCache.GetPeeredPrefixes(uint32(vni))
		c.log.V(1).Info("GetPeerVnis", "VNI", vni, "mbPeerVnis", mbPeerVnis, "peeredPrefixes", peeredPrefixes)

		for _, peeredVNI := range mbPeerVnis.UnsortedList() {
			// by default, we add the route if no peered prefixes are set
			addRoute := true
			if ok {
				allowedPeeredPrefixes, exists := peeredPrefixes[peeredVNI]
				// if we have set peered prefixes for this VNI, we need to check if the destination is in the list
				if exists {
					// if the destination is not in the list of peered prefixes, we don't add the route
					addRoute = false
					for _, peeredPrefix := range allowedPeeredPrefixes {
						if peeredPrefix.Contains(dest.Prefix.Addr()) {
							addRoute = true
							break
						}
					}
				}
			}

			if addRoute {
				if err := c.addLocalRoute(vni, mb.VNI(peeredVNI), dest, hop); err != nil {
					errStrs = append(errStrs, err.Error())
				}
			}
		}
	}

	if len(errStrs) > 0 {
		return errors.New(strings.Join(errStrs, "\n"))
	}

	return nil
}

func (c *MetalnetClient) RemoveRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	c.log.V(1).Info("RemoveRoute", "VNI", vni, "dest", dest, "hop", hop)
	var errStrs []string

	isDefaultRoute, err := c.FilterDefaultRoute(RemoveDefaultRoute, vni, dest, hop)
	if err != nil {
		return fmt.Errorf("error handling default router change: %w", err)
	} else if isDefaultRoute {
		return nil
	}

	if err := c.removeLocalRoute(vni, vni, dest, hop); err != nil {
		errStrs = append(errStrs, err.Error())
	}

	mbPeerVnis, _ := c.metalnetCache.GetPeerVnis(uint32(vni))

	for _, peeredVNI := range mbPeerVnis.UnsortedList() {
		if hop.Type == mbproto.NextHopType_STANDARD {
			if err := c.removeLocalRoute(vni, mb.VNI(peeredVNI), dest, hop); err != nil {
				errStrs = append(errStrs, err.Error())
			}
		}
	}

	if len(errStrs) > 0 {
		return errors.New(strings.Join(errStrs, "\n"))
	}

	return nil
}

func (c *MetalnetClient) CleanupNotPeeredRoutes(vni uint32) error {
	ctx := context.Background()
	routes, err := c.dpdk.ListRoutes(ctx, vni)
	if err != nil {
		return fmt.Errorf("error listing dpdk routes for vni %d: %w", vni, err)
	}

	set, ok := c.metalnetCache.GetPeerVnis(uint32(vni))

	// loop over all routes and delete the ones that are not peered
	for _, route := range routes.Items {
		// only delete route if it is not the local vni and not peered
		if route.Spec.NextHop.VNI != vni && (ok && !set.Has(route.Spec.NextHop.VNI)) {
			if _, err := c.dpdk.DeleteRoute(
				ctx,
				vni,
				route.Spec.Prefix,
				dpdkerrors.Ignore(dpdkerrors.NO_VNI, dpdkerrors.ROUTE_NOT_FOUND, dpdkerrors.ROUTE_BAD_PORT),
			); err != nil {
				return fmt.Errorf("error deleting route: %w", err)
			}
		}
	}

	return nil
}

func (c *MetalnetClient) SetDefaultRouterAddress(address netip.Addr) {
	c.DefaultRouterAddress.RouterAddress = address
	c.DefaultRouterAddress.SetBySubsciption = true
}

func (c *MetalnetClient) handleDefaultRouterChange(operation DefaultRouteOperation) error {

	defaultRoutePrefix := netip.MustParsePrefix("0.0.0.0/0")
	ctx := context.Background()

	existingVNIs := c.mbInstance.GetSubscribedVnis()

	for _, vni := range existingVNIs {
		if uint32(vni) == c.DefaultRouterAddress.PublicVNI {
			continue
		}

		if operation == RemoveDefaultRoute {
			if _, err := c.dpdk.DeleteRoute(
				ctx,
				uint32(vni),
				&defaultRoutePrefix,
				dpdkerrors.Ignore(dpdkerrors.NO_VNI, dpdkerrors.ROUTE_NOT_FOUND, dpdkerrors.ROUTE_BAD_PORT),
			); err != nil {
				return fmt.Errorf("error deleting default route: %w", err)
			}
		}

		if operation == AddDefaultRoute {
			if _, err := c.dpdk.CreateRoute(ctx, &dpdk.Route{
				RouteMeta: dpdk.RouteMeta{
					VNI: uint32(vni),
				},
				Spec: dpdk.RouteSpec{
					Prefix: &defaultRoutePrefix,
					NextHop: &dpdk.RouteNextHop{
						VNI: uint32(vni),
						IP:  &c.DefaultRouterAddress.RouterAddress,
					},
				},
			},
				dpdkerrors.Ignore(dpdkerrors.ROUTE_EXISTS),
			); err != nil {
				return fmt.Errorf("error creating default route: %w", err)
			}

		}

	}

	return nil
}

func (c *MetalnetClient) FilterDefaultRoute(operation DefaultRouteOperation, vni mb.VNI, dest mb.Destination, hop mb.NextHop) (bool, error) {
	if uint32(vni) != c.DefaultRouterAddress.PublicVNI {
		return false, nil
	}

	if dest.Prefix.String() != "0.0.0.0/0" {
		return false, nil
	}

	c.DefaultRouterAddress.RWMutex.Lock()
	defer c.DefaultRouterAddress.RWMutex.Unlock()

	if operation == AddDefaultRoute {
		c.SetDefaultRouterAddress(hop.TargetAddress)
	} else {
		c.SetDefaultRouterAddress(netip.Addr{})
	}

	if err := c.handleDefaultRouterChange(operation); err != nil {
		return true, fmt.Errorf("error handling default router change: %w, operation %d", err, operation)
	}

	return true, nil
}
