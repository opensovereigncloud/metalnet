// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	mlsbondpb "mlsbond/proto"
)

const (
	// how long a reset waits for a step that may be on its way, far longer than a stream takes to open
	lateStepWait = time.Second
	// how long after the reset returned such a step reaches metalnet, far longer than metalnet takes
	// to take in that it did
	lateStepDelay = 200 * time.Millisecond
)

// lateStepProxy sits between metalnet and its mlsbond client, and makes the worst of what the network
// and the scheduler may do: a step the client sent before a dataplane reset reaches metalnet only
// after that reset has returned. By then the client has forgotten that step.
type lateStepProxy struct {
	mlsbondpb.UnimplementedClientAPIServer
	address  string
	server   *grpc.Server
	conn     *grpc.ClientConn
	upstream mlsbondpb.ClientAPIClient

	stepSeen      chan struct{}
	seenOnce      sync.Once
	resetReturned chan struct{}
	returnedOnce  sync.Once
}

func newLateStepProxy(upstream string) *lateStepProxy {
	GinkgoHelper()
	conn, err := grpc.NewClient(upstream, grpc.WithTransportCredentials(insecure.NewCredentials()))
	Expect(err).NotTo(HaveOccurred())
	lis, err := net.Listen("tcp", "[::1]:0")
	Expect(err).NotTo(HaveOccurred())
	p := &lateStepProxy{
		address:       lis.Addr().String(),
		server:        grpc.NewServer(),
		conn:          conn,
		upstream:      mlsbondpb.NewClientAPIClient(conn),
		stepSeen:      make(chan struct{}),
		resetReturned: make(chan struct{}),
	}
	mlsbondpb.RegisterClientAPIServer(p.server, p)
	go func() { _ = p.server.Serve(lis) }()
	return p
}

// stop comes after metalnet is gone, as metalnet needs its client until then.
func (p *lateStepProxy) stop() {
	p.server.Stop()
	_ = p.conn.Close()
}

func (p *lateStepProxy) Init(ctx context.Context, req *mlsbondpb.InitRequest) (*mlsbondpb.InitResponse, error) {
	return p.upstream.Init(ctx, req)
}

func (p *lateStepProxy) Subscribe(ctx context.Context, req *mlsbondpb.SubscribeRequest) (*mlsbondpb.SubscribeResponse, error) {
	return p.upstream.Subscribe(ctx, req)
}

func (p *lateStepProxy) Unsubscribe(ctx context.Context, req *mlsbondpb.UnsubscribeRequest) (*mlsbondpb.UnsubscribeResponse, error) {
	return p.upstream.Unsubscribe(ctx, req)
}

func (p *lateStepProxy) Status(ctx context.Context, req *mlsbondpb.StatusRequest) (*mlsbondpb.StatusResponse, error) {
	return p.upstream.Status(ctx, req)
}

// DataplaneReset waits for a step to be on its way, if the stream is open for one to come.
func (p *lateStepProxy) DataplaneReset(ctx context.Context, req *mlsbondpb.DataplaneResetRequest) (*mlsbondpb.DataplaneResetResponse, error) {
	select {
	case <-p.stepSeen:
	case <-time.After(lateStepWait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	res, err := p.upstream.DataplaneReset(ctx, req)
	if err == nil {
		p.returnedOnce.Do(func() { close(p.resetReturned) })
	}
	return res, err
}

// WatchSecurityAssociations holds back what the client sends before the reset has returned.
func (p *lateStepProxy) WatchSecurityAssociations(down grpc.BidiStreamingServer[mlsbondpb.WatchRequest, mlsbondpb.Step]) error {
	up, err := p.upstream.WatchSecurityAssociations(down.Context())
	if err != nil {
		return err
	}
	go func() {
		for {
			req, err := down.Recv()
			if err != nil {
				_ = up.CloseSend()
				return
			}
			if err := up.Send(req); err != nil {
				return
			}
		}
	}()
	for {
		step, err := up.Recv()
		if err != nil {
			return err
		}
		select {
		case <-p.resetReturned:
		default:
			p.seenOnce.Do(func() { close(p.stepSeen) })
			select {
			case <-p.resetReturned:
				time.Sleep(lateStepDelay)
			case <-down.Context().Done():
				return down.Context().Err()
			}
		}
		if err := down.Send(step); err != nil {
			return err
		}
	}
}
