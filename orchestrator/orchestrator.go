// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

// Package orchestrator makes metalnet the orchestrator of its host's mlsbond client: it subscribes
// the VNIs whose Network encrypts, carries out the client's steps in dpservice, and reports the
// result in the Network's status.
//
// It keeps no state on disk. A restarted metalnet takes the identities of what is installed from
// dpservice, and hands them to the mlsbond client as its inventory.
package orchestrator

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkclient "github.com/ironcore-dev/dpservice/go/dpservice-go/client"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"mlsbond"
)

const (
	stepTimeout = 5 * time.Second
	// how long a reconcile that needs the mlsbond client waits for it
	clientTimeout = 5 * time.Second
	// how long one that does not need it does, as a stuck client must not stall its routes
	probeTimeout = time.Second
	// how soon a status write that failed is tried again
	statusRetry = 5 * time.Second

	noClientMessage = "encryption requested, but this metalnet has no mlsbond client configured"
)

// Orchestrator is created once per metalnet. Start it with the manager.
type Orchestrator struct {
	client   client.Client
	reader   client.Reader
	dpdk     dpdkclient.Client
	nodeName string
	address  string
	log      logr.Logger
	wake     chan struct{}

	mtx sync.Mutex
	// connected on demand, see Reconcile
	conn *mlsbond.Conn
	// the Security Associations in dpservice
	installed map[mlsbond.SecurityAssociationID]bool
	// the dpservice is new and the mlsbond client does not know yet, so steps must not reach it
	resetPending bool
	// VNIs the mlsbond client is subscribed to, as far as known
	subscribed map[uint32]bool
	// VNIs found unwanted while not connected: an earlier metalnet may have subscribed them
	unwanted map[uint32]bool
	// VNI -> Network, while it encrypts on this host
	networks map[uint32]types.NamespacedName
	// why a VNI cannot be subscribed
	blocked map[uint32]string
	// the last failed install per VNI and peer
	failures map[uint32]map[netip.Addr]string
	// each Network's entry for this host, as it should be and as last written
	desired map[types.NamespacedName]metalnetv1alpha1.NetworkEncryptionStatus
	written map[types.NamespacedName]metalnetv1alpha1.NetworkEncryptionStatus
	keyFile *keyFile
}

// Options are the Orchestrator's dependencies.
type Options struct {
	// Client writes the Network status.
	Client client.Client
	// Reader reads Networks before the manager's cache has started.
	Reader   client.Reader
	DPDK     dpdkclient.Client
	NodeName string
	// Address of the mlsbond client; empty if there is none.
	Address string
	// KeyFile, if set, receives raw keys and salts. For debugging only.
	KeyFile string
}

// New returns an Orchestrator that holds nothing yet.
func New(opts Options) *Orchestrator {
	o := &Orchestrator{
		client:     opts.Client,
		reader:     opts.Reader,
		dpdk:       opts.DPDK,
		nodeName:   opts.NodeName,
		address:    opts.Address,
		log:        log.Log.WithName("orchestrator"),
		wake:       make(chan struct{}, 1),
		installed:  map[mlsbond.SecurityAssociationID]bool{},
		subscribed: map[uint32]bool{},
		unwanted:   map[uint32]bool{},
		networks:   map[uint32]types.NamespacedName{},
		blocked:    map[uint32]string{},
		failures:   map[uint32]map[netip.Addr]string{},
		desired:    map[types.NamespacedName]metalnetv1alpha1.NetworkEncryptionStatus{},
		written:    map[types.NamespacedName]metalnetv1alpha1.NetworkEncryptionStatus{},
	}
	if opts.KeyFile != "" {
		o.keyFile = newKeyFile(opts.KeyFile)
	}
	return o
}

// ResetStatus sets this host's entries to Pending, so that a Ready from before never outlives the
// keys. It runs before anything else touches them; what is still installed makes them Ready again.
func (o *Orchestrator) ResetStatus(ctx context.Context) error {
	networks := &metalnetv1alpha1.NetworkList{}
	if err := o.reader.List(ctx, networks); err != nil {
		return fmt.Errorf("error listing networks: %w", err)
	}
	for i := range networks.Items {
		network := &networks.Items[i]
		if !slices.ContainsFunc(network.Status.Encryption, func(e metalnetv1alpha1.NetworkEncryptionStatus) bool {
			return e.NodeName == o.nodeName
		}) {
			continue
		}
		key := client.ObjectKeyFromObject(network)
		entry := metalnetv1alpha1.NetworkEncryptionStatus{NodeName: o.nodeName, State: metalnetv1alpha1.EncryptionStatePending}
		if err := o.writeEntry(ctx, key, &entry); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("error resetting encryption status of network %s: %w", key, err)
		}
		o.desired[key] = entry
		o.written[key] = entry
	}
	return nil
}

// LoadInventory takes the Security Associations a running dpservice holds. A dpservice that metalnet
// had to initialize is new: it holds none, and the mlsbond client has to be told, see connect.
func (o *Orchestrator) LoadInventory(ctx context.Context, dataplaneIsNew bool) error {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	o.resetPending = dataplaneIsNew
	if !dataplaneIsNew {
		list, err := o.dpdk.ListSecurityAssociations(ctx)
		if err != nil {
			return fmt.Errorf("error listing security associations: %w", err)
		}
		for i := range list.Items {
			id, err := idFromMeta(&list.Items[i].SecurityAssociationMeta)
			if err != nil {
				return err
			}
			o.installed[id] = true
		}
		o.log.Info("Took the inventory of dpservice", "SecurityAssociations", len(o.installed))
	}
	if o.keyFile != nil {
		return o.keyFile.load(o.installed)
	}
	return nil
}

// Reconcile brings this host's membership of the Network's VNI group in line with its spec. inUse
// tells that an interface exists in dpservice, expected that one is about to.
func (o *Orchestrator) Reconcile(ctx context.Context, network *metalnetv1alpha1.Network, inUse, expected bool) error {
	vni := uint32(network.Spec.ID)
	key := client.ObjectKeyFromObject(network)
	want := network.Spec.Encrypt && network.DeletionTimestamp.IsZero() && (inUse || expected)

	if want {
		o.addNetwork(vni, key)
	} else {
		o.removeNetwork(vni, key)
	}

	if o.address == "" || !inUse {
		// without an interface, there is no host prefix to connect with
		if want {
			return nil
		}
		return o.leave(ctx, vni)
	}

	// Without a Network that wants it, this only finds out what an earlier metalnet subscribed.
	timeout := clientTimeout
	if !want && !o.isSubscribed(vni) {
		timeout = probeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := o.connect(ctx); err != nil {
		if want {
			o.setBlocked(vni, err)
			return err
		}
		if o.isSubscribed(vni) {
			return err
		}
		o.log.V(1).Info("Cannot reach the mlsbond client, while nothing needs it", "Error", err.Error())
		return nil
	}
	if want {
		if err := o.join(ctx, vni); err != nil {
			o.setBlocked(vni, err)
			return err
		}
		o.setBlocked(vni, nil)
		return nil
	}
	return o.leave(ctx, vni)
}

func (o *Orchestrator) isSubscribed(vni uint32) bool {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	return o.subscribed[vni]
}

func (o *Orchestrator) addNetwork(vni uint32, key types.NamespacedName) {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	o.networks[vni] = key
	delete(o.unwanted, vni)
	o.refreshLocked(vni)
}

func (o *Orchestrator) removeNetwork(vni uint32, key types.NamespacedName) {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	delete(o.networks, vni)
	delete(o.blocked, vni)
	delete(o.failures, vni)
	delete(o.desired, key)
	if o.conn == nil {
		o.unwanted[vni] = true
	}
	o.signal()
}

// setBlocked records why vni cannot be subscribed, or that nothing stands in the way any more.
func (o *Orchestrator) setBlocked(vni uint32, err error) {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	if err == nil {
		delete(o.blocked, vni)
	} else {
		o.blocked[vni] = err.Error()
	}
	o.refreshLocked(vni)
}

// connect connects to the mlsbond client unless that happened already, and tells it of a new
// dpservice: until it knows, it may still ask for Security Associations of the old one. Only the
// Network controller calls it, one reconcile at a time.
func (o *Orchestrator) connect(ctx context.Context) error {
	o.mtx.Lock()
	conn := o.conn
	o.mtx.Unlock()

	if conn == nil {
		var err error
		if conn, err = o.dial(ctx); err != nil {
			return err
		}
	}

	o.mtx.Lock()
	resetPending := o.resetPending
	o.mtx.Unlock()
	if resetPending {
		if err := conn.DataplaneReset(ctx); err != nil {
			return fmt.Errorf("error reporting the dataplane reset to the mlsbond client: %w", err)
		}
		o.log.Info("Reported the new dpservice to the mlsbond client")
		o.mtx.Lock()
		o.resetPending = false
		o.mtx.Unlock()
	}
	return nil
}

func (o *Orchestrator) dial(ctx context.Context) (*mlsbond.Conn, error) {
	prefix, err := o.hostPrefix(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := mlsbond.Connect(ctx, o.address, o.nodeName, prefix, o)
	if err != nil {
		return nil, fmt.Errorf("error connecting to the mlsbond client %s: %w", o.address, err)
	}
	st, err := conn.Status(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error asking the mlsbond client %s for its status: %w", o.address, err)
	}
	o.log.Info("Connected to the mlsbond client", "Address", o.address, "HostPrefix", prefix, "VNIs", st.VNIs)

	o.mtx.Lock()
	o.conn = conn
	// A metalnet that initialized dpservice may have died before it could tell the mlsbond client.
	// A pair holding what dpservice does not hold gives that away, with nothing stored anywhere.
	if !o.resetPending && o.lostAssociationsLocked(st) {
		o.log.Info("The mlsbond client has pairs whose Security Associations dpservice does not hold")
		o.resetPending = true
	}
	// What an earlier metalnet subscribed is unsubscribed if it is not wanted any more. Whether it
	// is, those not looked at yet find out when their Network is reconciled.
	var unwanted []uint32
	for _, vni := range st.VNIs {
		if o.unwanted[vni] {
			unwanted = append(unwanted, vni)
		} else {
			o.subscribed[vni] = true
		}
	}
	clear(o.unwanted)
	o.mtx.Unlock()

	for _, vni := range unwanted {
		if err := conn.Unsubscribe(ctx, vni); err != nil {
			// conn repeats it
			o.log.Error(err, "Error unsubscribing", "VNI", vni)
		}
	}
	return conn, nil
}

// lostAssociationsLocked tells whether a pair of the mlsbond client has a Security Association that
// is not installed.
func (o *Orchestrator) lostAssociationsLocked(st *mlsbond.Status) bool {
	held := func(vni uint32, direction mlsbond.Direction, spi uint32) bool {
		for id := range o.installed {
			if id.VNI == vni && id.Direction == direction && id.SPI == spi {
				return true
			}
		}
		return false
	}
	for _, p := range st.Pairs {
		if p.EgressSPI != 0 && !held(p.VNI, mlsbond.Egress, p.EgressSPI) {
			return true
		}
		for _, spi := range p.IngressSPIs {
			if !held(p.VNI, mlsbond.Ingress, spi) {
				return true
			}
		}
	}
	return false
}

// hostPrefix takes the host prefix from an interface's underlay address.
func (o *Orchestrator) hostPrefix(ctx context.Context) (netip.Prefix, error) {
	ifaces, err := o.dpdk.ListInterfaces(ctx)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("error listing interfaces: %w", err)
	}
	for i := range ifaces.Items {
		if underlay := ifaces.Items[i].Spec.UnderlayRoute; underlay != nil {
			return netip.PrefixFrom(*underlay, 64).Masked(), nil
		}
	}
	return netip.Prefix{}, errors.New("no interface with an underlay address")
}

// join subscribes vni. It does so even if the mlsbond client has it already: the connection repeats
// what was subscribed through it whenever the client restarts. It does that for a failed call too,
// so that this counts as subscribed from here on.
func (o *Orchestrator) join(ctx context.Context, vni uint32) error {
	o.mtx.Lock()
	conn := o.conn
	if !o.subscribed[vni] {
		o.log.Info("Subscribing at the mlsbond client", "VNI", vni)
		o.subscribed[vni] = true
	}
	o.mtx.Unlock()

	if err := conn.Subscribe(ctx, vni); err != nil {
		return fmt.Errorf("error subscribing vni %d at the mlsbond client: %w", vni, err)
	}
	return nil
}

// leave unsubscribes vni, which removes its Security Associations through the usual steps.
func (o *Orchestrator) leave(ctx context.Context, vni uint32) error {
	o.mtx.Lock()
	conn, subscribed := o.conn, o.subscribed[vni]
	o.mtx.Unlock()

	if conn == nil || !subscribed {
		return nil
	}
	if err := conn.Unsubscribe(ctx, vni); err != nil {
		return fmt.Errorf("error unsubscribing vni %d: %w", vni, err)
	}
	o.log.Info("Unsubscribed at the mlsbond client", "VNI", vni)
	o.mtx.Lock()
	defer o.mtx.Unlock()
	delete(o.subscribed, vni)
	return nil
}

// refreshLocked works out the entry of vni from what is installed, and wakes the status writer if
// it changed. It is called with mtx held.
func (o *Orchestrator) refreshLocked(vni uint32) {
	key, ok := o.networks[vni]
	if !ok {
		return
	}
	entry := metalnetv1alpha1.NetworkEncryptionStatus{
		NodeName: o.nodeName,
		State:    metalnetv1alpha1.EncryptionStatePending,
		Message:  o.messageLocked(vni),
	}
	if o.readyLocked(vni) {
		entry.State = metalnetv1alpha1.EncryptionStateReady
	}
	if o.desired[key] != entry {
		o.desired[key] = entry
		o.signal()
	}
}

// readyLocked tells whether egress and ingress are installed for at least one peer.
func (o *Orchestrator) readyLocked(vni uint32) bool {
	egress := map[netip.Addr]bool{}
	ingress := map[netip.Addr]bool{}
	for id := range o.installed {
		if id.VNI != vni {
			continue
		}
		if id.Direction == mlsbond.Egress {
			egress[id.Dst] = true
		} else {
			ingress[id.Src] = true
		}
	}
	for peer := range egress {
		if ingress[peer] {
			return true
		}
	}
	return false
}

func (o *Orchestrator) messageLocked(vni uint32) string {
	if o.address == "" {
		return noClientMessage
	}
	failures := o.failures[vni]
	messages := make([]string, 0, len(failures)+1)
	if blocked, ok := o.blocked[vni]; ok {
		messages = append(messages, blocked)
	}
	for _, peer := range slices.SortedFunc(maps.Keys(failures), netip.Addr.Compare) {
		messages = append(messages, failures[peer])
	}
	return strings.Join(messages, "; ")
}

func (o *Orchestrator) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// Start writes this host's entries whenever they change, without going through a reconcile. A
// status write costs dpservice nothing, and steps never wait for the API server.
func (o *Orchestrator) Start(ctx context.Context) error {
	// when a status write failed, or there are failures to look after
	retry := time.NewTimer(statusRetry)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			o.mtx.Lock()
			conn := o.conn
			o.mtx.Unlock()
			if conn != nil {
				return conn.Close()
			}
			return nil
		case <-o.wake:
		case <-retry.C:
		}
		o.dropFailuresOfEndedPairs(ctx)
		if !o.writeChanged(ctx) || o.hasFailures() {
			retry.Reset(statusRetry)
		}
	}
}

func (o *Orchestrator) hasFailures() bool {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	for _, failures := range o.failures {
		if len(failures) > 0 {
			return true
		}
	}
	return false
}

// dropFailuresOfEndedPairs covers what no step will: a pair that ends with nothing installed has
// nothing to remove, so that the failure of its install would stay.
func (o *Orchestrator) dropFailuresOfEndedPairs(ctx context.Context) {
	if !o.hasFailures() {
		return
	}
	o.mtx.Lock()
	conn := o.conn
	o.mtx.Unlock()
	if conn == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	st, err := conn.Status(ctx)
	if err != nil {
		return
	}

	o.mtx.Lock()
	defer o.mtx.Unlock()
	for vni, failures := range o.failures {
		for peer := range failures {
			if !slices.ContainsFunc(st.Pairs, func(p mlsbond.PairStatus) bool { return p.VNI == vni && p.Peer.Addr() == peer }) {
				delete(failures, peer)
				o.refreshLocked(vni)
			}
		}
	}
}

// writeChanged returns false if any write failed.
func (o *Orchestrator) writeChanged(ctx context.Context) bool {
	o.mtx.Lock()
	desired := maps.Clone(o.desired)
	written := maps.Clone(o.written)
	o.mtx.Unlock()

	ok := true
	for key := range written {
		if _, wanted := desired[key]; wanted {
			continue
		}
		if err := o.writeEntry(ctx, key, nil); client.IgnoreNotFound(err) != nil {
			o.log.Error(err, "Error removing encryption status", "Network", key)
			ok = false
			continue
		}
		o.mtx.Lock()
		delete(o.written, key)
		o.mtx.Unlock()
	}
	for key, entry := range desired {
		if have, found := written[key]; found && have == entry {
			continue
		}
		if err := o.writeEntry(ctx, key, &entry); client.IgnoreNotFound(err) != nil {
			o.log.Error(err, "Error writing encryption status", "Network", key)
			ok = false
			continue
		}
		o.mtx.Lock()
		o.written[key] = entry
		o.mtx.Unlock()
	}
	return ok
}

// Step implementation: mlsbond.Client and mlsbond.Inventory.

func apiMeta(id mlsbond.SecurityAssociationID) dpdk.SecurityAssociationMeta {
	return dpdk.SecurityAssociationMeta{Vni: id.VNI, Spi: id.SPI, Direction: id.Direction.String(), SrcUnderlay: &id.Src, DstUnderlay: &id.Dst}
}

func idFromMeta(meta *dpdk.SecurityAssociationMeta) (mlsbond.SecurityAssociationID, error) {
	id := mlsbond.SecurityAssociationID{VNI: meta.Vni, SPI: meta.Spi}
	switch strings.ToLower(meta.Direction) {
	case "egress":
		id.Direction = mlsbond.Egress
	case "ingress":
		id.Direction = mlsbond.Ingress
	default:
		return id, fmt.Errorf("security association %s has direction %q", meta.GetName(), meta.Direction)
	}
	if meta.SrcUnderlay == nil || meta.DstUnderlay == nil {
		return id, fmt.Errorf("security association %s has no underlay addresses", meta.GetName())
	}
	id.Src, id.Dst = *meta.SrcUnderlay, *meta.DstUnderlay
	return id, nil
}

func apiSpec(sa mlsbond.SecurityAssociation) dpdk.SecurityAssociationSpec {
	return dpdk.SecurityAssociationSpec{
		Algorithm:    sa.Algorithm,
		Key:          hex.EncodeToString(sa.Key),
		Salt:         hex.EncodeToString(sa.Salt),
		ReplayWindow: sa.ReplayWindow,
		Esn:          sa.ESN,
	}
}

func peerOf(id mlsbond.SecurityAssociationID) netip.Addr {
	if id.Direction == mlsbond.Egress {
		return id.Dst
	}
	return id.Src
}

// step carries out one step in dpservice. A failure goes back to the mlsbond client, which retries.
func (o *Orchestrator) step(do func(ctx context.Context) error) error {
	o.mtx.Lock()
	resetPending := o.resetPending
	o.mtx.Unlock()
	if resetPending {
		return errors.New("dpservice is new, waiting for the mlsbond client to learn of it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	return do(ctx)
}

func (o *Orchestrator) installFailedLocked(id mlsbond.SecurityAssociationID, err error) {
	// failing after the VNI was left, which ends the pair
	if _, ok := o.networks[id.VNI]; !ok {
		return
	}
	failures := o.failures[id.VNI]
	if failures == nil {
		failures = map[netip.Addr]string{}
		o.failures[id.VNI] = failures
	}
	failures[peerOf(id)] = fmt.Sprintf("error installing %s: %v", id, err)
	o.refreshLocked(id.VNI)
}

// installedLocked records that an install succeeded, which ends the peer's failure.
func (o *Orchestrator) installedLocked(id mlsbond.SecurityAssociationID) {
	delete(o.failures[id.VNI], peerOf(id))
	o.changedLocked(id)
}

func (o *Orchestrator) changedLocked(id mlsbond.SecurityAssociationID) {
	o.refreshLocked(id.VNI)
	if o.keyFile != nil {
		if err := o.keyFile.write(); err != nil {
			o.log.Error(err, "Error writing the debug key file")
		}
	}
}

// AddSecurityAssociation installs an ingress or the first egress of a pair.
func (o *Orchestrator) AddSecurityAssociation(sa mlsbond.SecurityAssociation) error {
	meta := apiMeta(sa.ID)
	assoc := dpdk.SecurityAssociation{SecurityAssociationMeta: meta, Spec: apiSpec(sa)}
	err := o.step(func(ctx context.Context) error {
		_, err := o.dpdk.CreateSecurityAssociation(ctx, &assoc)
		if dpdkerrors.IsStatusErrorCode(err, dpdkerrors.SA_EXISTS) {
			return o.replaceExisting(ctx, &assoc)
		}
		return err
	})

	o.mtx.Lock()
	defer o.mtx.Unlock()
	if err != nil {
		o.installFailedLocked(sa.ID, err)
		return fmt.Errorf("error creating security association %s: %w", meta.GetName(), err)
	}
	o.installed[sa.ID] = true
	if o.keyFile != nil {
		o.keyFile.add(sa)
	}
	o.installedLocked(sa.ID)
	return nil
}

// replaceExisting handles a step repeated after a crash: an association that is in place counts as
// done, and keeps its sequence numbers, since starting them anew under the same key would repeat
// AES-GCM nonces. An association with other keys under the same identity is replaced.
func (o *Orchestrator) replaceExisting(ctx context.Context, assoc *dpdk.SecurityAssociation) error {
	have, err := o.dpdk.GetSecurityAssociation(ctx, &assoc.SecurityAssociationMeta)
	if err != nil {
		return err
	}
	if strings.EqualFold(have.Spec.Key, assoc.Spec.Key) && strings.EqualFold(have.Spec.Salt, assoc.Spec.Salt) {
		return nil
	}
	if _, err := o.dpdk.DeleteSecurityAssociation(ctx, &assoc.SecurityAssociationMeta); err != nil {
		return err
	}
	_, err = o.dpdk.CreateSecurityAssociation(ctx, assoc)
	return err
}

// UpdateSecurityAssociation switches a pair's egress to a new epoch. Repeated after a crash, the old
// one is gone and the new one is in the inventory.
func (o *Orchestrator) UpdateSecurityAssociation(old mlsbond.SecurityAssociationID, sa mlsbond.SecurityAssociation) error {
	meta := apiMeta(old)
	err := o.step(func(ctx context.Context) error {
		_, err := o.dpdk.UpdateSecurityAssociation(ctx, &meta, &dpdk.SecurityAssociationUpdate{NewSpi: sa.ID.SPI, Spec: apiSpec(sa)})
		if dpdkerrors.IsStatusErrorCode(err, dpdkerrors.SA_NOT_FOUND) {
			o.mtx.Lock()
			defer o.mtx.Unlock()
			if o.installed[sa.ID] {
				return nil
			}
		}
		return err
	})

	o.mtx.Lock()
	defer o.mtx.Unlock()
	if err != nil {
		o.installFailedLocked(sa.ID, err)
		return fmt.Errorf("error switching security association %s to spi %d: %w", meta.GetName(), sa.ID.SPI, err)
	}
	delete(o.installed, old)
	o.installed[sa.ID] = true
	if o.keyFile != nil {
		o.keyFile.remove(old)
		o.keyFile.add(sa)
	}
	o.installedLocked(sa.ID)
	return nil
}

// RemoveSecurityAssociation removes an old ingress, or one of a pair that ended.
func (o *Orchestrator) RemoveSecurityAssociation(id mlsbond.SecurityAssociationID) error {
	meta := apiMeta(id)
	err := o.step(func(ctx context.Context) error {
		_, err := o.dpdk.DeleteSecurityAssociation(ctx, &meta, dpdkerrors.Ignore(dpdkerrors.SA_NOT_FOUND))
		return err
	})
	if err != nil {
		return fmt.Errorf("error deleting security association %s: %w", meta.GetName(), err)
	}

	o.mtx.Lock()
	defer o.mtx.Unlock()
	delete(o.installed, id)
	if o.keyFile != nil {
		o.keyFile.remove(id)
	}
	o.changedLocked(id)
	return nil
}

// SecurityAssociations is the inventory handed to the mlsbond client on every connect.
func (o *Orchestrator) SecurityAssociations() []mlsbond.SecurityAssociationID {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	return slices.Collect(maps.Keys(o.installed))
}
