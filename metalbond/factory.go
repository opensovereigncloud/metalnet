package metalbond

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	mb "github.com/onmetal/metalbond"
	"github.com/onmetal/metalnet/dpdk"
	"github.com/onmetal/metalnet/dpdkmetalbond"
)

type MetalbondFactory struct {
	Config            mb.Config
	Peers             []string
	ClientOptions     dpdkmetalbond.ClientOptions
	DPDK              dpdk.Client
	metalbondClients  map[uint32]Client
	metalbondInternal map[uint32]dpdkmetalbond.MbInternalAccess
	metalbondInstance map[uint32]*mb.MetalBond
	log               logr.Logger
}

func (c *MetalbondFactory) Init() {
	c.metalbondInternal = make(map[uint32]dpdkmetalbond.MbInternalAccess)
	c.metalbondClients = make(map[uint32]Client)
	c.metalbondInstance = make(map[uint32]*mb.MetalBond)
}

func (c *MetalbondFactory) New(ctx context.Context, vni uint32) error {
	var err error
	c.log, err = logr.FromContext(ctx)
	if err != nil {
		return err
	}

	c.log.Info("creating new metalbond instance", "vni", vni)
	var mbClient dpdkmetalbond.MbInternalAccess

	mbClient, err = dpdkmetalbond.NewClient(c.DPDK, c.ClientOptions, vni)
	if err != nil {
		return err
	}

	mbInstance := mb.NewMetalBond(c.Config, mbClient)
	metalbondClient := NewClient(mbInstance)

	for _, metalbondPeer := range c.Peers {
		if err := mbInstance.AddPeer(metalbondPeer, ""); err != nil {
			return err
		}
		if c.waitForEstablishedPeer(mbInstance, metalbondPeer) {
			c.log.Info("metalbond client connection is established", "vni", vni)
		} else {
			return fmt.Errorf("metalbond client connection is not established")
		}
	}

	c.metalbondInternal[vni] = mbClient
	c.metalbondClients[vni] = metalbondClient
	c.metalbondInstance[vni] = mbInstance

	return nil
}
func (c *MetalbondFactory) Ready(vni uint32) bool {
	if internal, ok := c.metalbondInternal[vni]; !ok || internal == nil {
		return false
	}
	if client, ok := c.metalbondClients[vni]; !ok || client == nil {
		return false
	}

	return true
}

func (c *MetalbondFactory) Client(vni uint32) Client {
	return c.metalbondClients[vni]
}

func (c *MetalbondFactory) Internal(vni uint32) dpdkmetalbond.MbInternalAccess {
	return c.metalbondInternal[vni]
}

func (c *MetalbondFactory) waitForEstablishedPeer(instance *mb.MetalBond, addr string) bool {
	// Call the PeerState function repeatedly until it returns true or a timeout is reached
	timeout := 30 * time.Second
	start := time.Now()
	for {
		state, err := instance.PeerState(addr)
		if err == nil && state == mb.ESTABLISHED {
			return true
		}

		if time.Since(start) >= timeout {
			c.log.Error(fmt.Errorf("timeout reached while waiting for peer (%s) to reach expected state %s", addr, mb.ESTABLISHED), "peer not ready")
			return false
		}

		// Wait a short time before checking again
		time.Sleep(500 * time.Millisecond)
	}
}

func (c *MetalbondFactory) Cleanup(vni uint32) {
	mbInstance := c.metalbondInstance[vni]
	if mbInstance != nil {
		mbInstance.Shutdown()
	}
	delete(c.metalbondInstance, vni)
	delete(c.metalbondInternal, vni)
	delete(c.metalbondClients, vni)
}
