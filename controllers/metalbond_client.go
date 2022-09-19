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

package controllers

import (
	"context"
	"fmt"
	"net"

	mb "github.com/onmetal/metalbond"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
)

type MetalbondClient struct {
	config MetalbondClientConfig
}

type MetalbondClientConfig struct {
	DPDKonmetalClient dpdkproto.DPDKonmetalClient
	IPv4Only          bool
}

func NewMetalbondClient(config MetalbondClientConfig) (*MetalbondClient, error) {
	return &MetalbondClient{
		config: config,
	}, nil
}

func (c *MetalbondClient) AddRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	ctx := context.Background()

	if c.config.IPv4Only && dest.IPVersion != mb.IPV4 {
		// log.Infof("Received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
		return fmt.Errorf("received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
	}

	_, dst, err := net.ParseCIDR(dest.Prefix.String())
	if err != nil {
		return fmt.Errorf("cannot parse destination prefix: %v", err)
	}

	prefix := &dpdkproto.Prefix{
		PrefixLength: uint32(dest.Prefix.Bits()),
	}

	prefix.IpVersion = dpdkproto.IPVersion_IPv4 //only ipv4 in overlay is supported so far
	prefix.Address = []byte(dst.IP.String())

	req := &dpdkproto.VNIRouteMsg{
		Vni: &dpdkproto.VNIMsg{Vni: uint32(vni)},
		Route: &dpdkproto.Route{
			IpVersion:      dpdkproto.IPVersion_IPv6, //only ipv4 in overlay is supported so far
			Weight:         100,                      // this field is ignored in dp-service
			Prefix:         prefix,
			NexthopVNI:     uint32(vni),
			NexthopAddress: []byte(hop.TargetAddress.String()),
		},
	}

	status, err := c.config.DPDKonmetalClient.AddRoute(ctx, req)
	if err != nil || (status.Error != 0 && status.Error != 251) {
		return fmt.Errorf("cannot add route to dpdk service: %v Status from DPDKClient: %d", err, status.Error)
	}
	return nil
}

func (c *MetalbondClient) RemoveRoute(vni mb.VNI, dest mb.Destination, hop mb.NextHop) error {
	ctx := context.Background()

	if c.config.IPv4Only && dest.IPVersion != mb.IPV4 {
		// log.Infof("Received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
		return fmt.Errorf("received non-IPv4 route will not be installed in kernel route table (IPv4-only mode)")
	}

	_, dst, err := net.ParseCIDR(dest.Prefix.String())
	if err != nil {
		return fmt.Errorf("cannot parse destination prefix: %v", err)
	}

	prefix := &dpdkproto.Prefix{
		PrefixLength: uint32(dest.Prefix.Bits()),
	}

	prefix.IpVersion = dpdkproto.IPVersion_IPv4 //only ipv4 in overlay is supported so far
	prefix.Address = []byte(dst.IP.String())

	req := &dpdkproto.VNIRouteMsg{
		Vni: &dpdkproto.VNIMsg{Vni: uint32(vni)},
		Route: &dpdkproto.Route{
			IpVersion:      dpdkproto.IPVersion_IPv6, //only ipv4 in overlay is supported so far
			Weight:         100,                      // this field is ignored in dp-service
			Prefix:         prefix,
			NexthopVNI:     uint32(vni),
			NexthopAddress: []byte(hop.TargetAddress.String()),
		},
	}

	status, err := c.config.DPDKonmetalClient.DeleteRoute(ctx, req)
	if err != nil || status.Error != 0 {
		return fmt.Errorf("cannot remove route from the dpdk service: %v, Status from DPDKClient: %d", err, status.Error)
	}

	return nil

}
