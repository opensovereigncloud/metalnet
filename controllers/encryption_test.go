// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkerrors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	metalnetapply "github.com/ironcore-dev/metalnet/api/v1alpha1/applyconfiguration/api/v1alpha1"

	"mlsbond"
	mlsbondpb "mlsbond/proto"
)

// These specs run what a host runs: the metalnet binary, with a real dpservice, mlsbond server and
// mlsbond client. The suite has one metalnet, so the other hosts of a VNI group are simulated with
// mlsbond's own Go package. Everything is observed from the outside: through the Kubernetes API,
// dpservice's gRPC interface, the simulated hosts and the frames dpservice sends.

const (
	encNode       = "enc-node"
	localPrefix   = "fc00:1::/64"
	encTimeout    = 20 * time.Second
	encPolling    = 100 * time.Millisecond
	encConsistent = 2 * time.Second
)

var _ = Describe("Encryption", Label("encryption"), Serial, func() {
	ctx := context.Background()

	var (
		env *encryptionEnv
		ns  *corev1.Namespace
	)

	BeforeEach(func() {
		if os.Getenv("DPSERVICE_RESTART_CMD") == "" {
			Skip("needs hack/test-controllers.sh")
		}
		env = newEncryptionEnv()
		ns = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "enc-"}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() {
			env.cleanUp(ctx, ns.Name)
		})
	})

	newNetwork := func(vni int32, encrypt bool) *metalnetv1alpha1.Network {
		GinkgoHelper()
		network := &metalnetv1alpha1.Network{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("net-%d", vni), Namespace: ns.Name},
			Spec:       metalnetv1alpha1.NetworkSpec{ID: vni, Encrypt: encrypt},
		}
		Expect(k8sClient.Create(ctx, network)).To(Succeed())
		return network
	}

	newInterface := func(network *metalnetv1alpha1.Network, name, ip string, encrypt bool) *metalnetv1alpha1.NetworkInterface {
		GinkgoHelper()
		node := encNode
		nic := &metalnetv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name},
			Spec: metalnetv1alpha1.NetworkInterfaceSpec{
				NetworkRef: corev1.LocalObjectReference{Name: network.Name},
				NodeName:   &node,
				IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				IPs:        []metalnetv1alpha1.IP{{Addr: netip.MustParseAddr(ip)}},
				Encrypt:    encrypt,
			},
		}
		Expect(k8sClient.Create(ctx, nic)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(nic), nic)).To(Succeed())
			g.Expect(nic.Status.TAPDevice).NotTo(BeNil())
		}, encTimeout, encPolling).Should(Succeed())
		return nic
	}

	setNetworkEncrypt := func(network *metalnetv1alpha1.Network, encrypt bool) {
		GinkgoHelper()
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
		base := network.DeepCopy()
		network.Spec.Encrypt = encrypt
		Expect(k8sClient.Patch(ctx, network, client.MergeFrom(base))).To(Succeed())
	}

	setInterfaceEncrypt := func(nic *metalnetv1alpha1.NetworkInterface, encrypt bool) {
		GinkgoHelper()
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(nic), nic)).To(Succeed())
		base := nic.DeepCopy()
		nic.Spec.Encrypt = encrypt
		Expect(k8sClient.Patch(ctx, nic, client.MergeFrom(base))).To(Succeed())
	}

	Describe("of a Network", func() {
		var (
			network *metalnetv1alpha1.Network
			vni     uint32
		)

		eventuallyReady := func() {
			GinkgoHelper()
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStateReady))
		}

		BeforeEach(func() {
			env.startMLSBond()
			env.startMetalnet()
			network = newNetwork(3100, true)
			vni = uint32(network.Spec.ID)
			newInterface(network, "vm", "10.31.0.1", false)
		})

		It("is Pending before any keys, Ready once egress and ingress are installed, and Pending when the last peer goes", func() {
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStatePending))
			Consistently(env.installed(ctx, vni), encConsistent, encPolling).Should(BeEmpty())

			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)

			peer.unsubscribe(vni)
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStatePending))
			Eventually(env.installed(ctx, vni), encTimeout, encPolling).Should(BeEmpty())
		})

		It("installs matching Security Associations on both ends", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()

			egress, ingress := env.expectPaired(ctx, peer, vni)
			for _, sa := range []*dpdk.SecurityAssociation{egress, ingress} {
				Expect(sa.Spec.Algorithm).To(ContainSubstring("gcm"))
				Expect(sa.Spec.Esn).To(BeTrue())
			}
			Expect(egress.Spec.ReplayWindow).To(BeZero())
			Expect(ingress.Spec.ReplayWindow).To(Equal(uint32(64)))
		})

		It("lists what is installed in the debug key file, root-only", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			egress, ingress := env.expectPaired(ctx, peer, vni)

			Eventually(env.keyFileSPIs, encTimeout, encPolling).Should(ConsistOf(egress.Spi, ingress.Spi))
			info, err := os.Stat(env.keyFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

			By("keeping the keys of what stays installed when metalnet restarts")
			env.restartMetalnet()
			eventuallyReady()
			Expect(env.keyFileEntry(egress.Spi)).To(HaveKeyWithValue("key", strings.ToLower(egress.Spec.Key)))
		})

		It("removes the associations and the entry when encryption is turned off", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)

			setNetworkEncrypt(network, false)
			Eventually(env.installed(ctx, vni), encTimeout, encPolling).Should(BeEmpty())
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(BeNil())
			Eventually(peer.orch.held, encTimeout, encPolling).Should(BeEmpty())
		})

		It("loses the entry and the associations with the last interface in the VNI", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()

			nic := &metalnetv1alpha1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "vm", Namespace: ns.Name}}
			Expect(k8sClient.Delete(ctx, nic)).To(Succeed())
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(BeNil())
			Eventually(env.installed(ctx, vni), encTimeout, encPolling).Should(BeEmpty())
		})

		It("gets fresh keys on both ends after a dpservice restart", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			oldEgress, oldIngress := env.expectPaired(ctx, peer, vni)

			// what happens in production: the health check fails, and metalnet is restarted
			env.restartDpservice()
			env.expectUnhealthy()
			env.stopMetalnet()
			env.startMetalnet()

			Eventually(func(g Gomega) {
				egress, ingress := env.pairedWith(ctx, g, peer, vni)
				g.Expect(egress.Spec.Key).NotTo(Equal(oldEgress.Spec.Key))
				g.Expect(ingress.Spec.Key).NotTo(Equal(oldIngress.Spec.Key))
			}, encTimeout, encPolling).Should(Succeed())
			eventuallyReady()
		})

		It("is Pending after a dpservice restart until keys arrive, saying why while the mlsbond client is away", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)

			env.clientProc.kill()
			env.restartDpservice()
			env.expectUnhealthy()
			env.restartMetalnet()
			Eventually(func(g Gomega) {
				entry := env.entry(ctx, network)
				g.Expect(entry).NotTo(BeNil())
				g.Expect(entry.State).To(Equal(metalnetv1alpha1.EncryptionStatePending))
				g.Expect(entry.Message).To(ContainSubstring("mlsbond client"))
			}, encTimeout, encPolling).Should(Succeed())
			Expect(env.installed(ctx, vni)()).To(BeEmpty())

			env.startMLSBondClient()
			Eventually(func(g Gomega) {
				entry := env.entry(ctx, network)
				g.Expect(entry).To(haveState(metalnetv1alpha1.EncryptionStateReady))
				g.Expect(entry.Message).To(BeEmpty())
			}, 2*encTimeout, encPolling).Should(Succeed())
			env.expectPaired(ctx, peer, vni)
		})

		It("gets fresh keys when the metalnet that initialized a new dpservice died before telling the mlsbond client", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			oldEgress, _ := env.expectPaired(ctx, peer, vni)

			env.stopMetalnet()
			env.restartDpservice()
			// all that metalnet got to do, so that the next one finds dpservice initialized and empty
			Eventually(func() error {
				_, err := dpdkClient.Initialize(ctx)
				return err
			}, encTimeout, encPolling).Should(Succeed())
			env.startMetalnet()

			Eventually(func(g Gomega) {
				egress, _ := env.pairedWith(ctx, g, peer, vni)
				g.Expect(egress.Spec.Key).NotTo(Equal(oldEgress.Spec.Key))
			}, encTimeout, encPolling).Should(Succeed())
			eventuallyReady()
		})

		// The step waiting for this metalnet is for the epoch the pair moved to while it was away.
		lateStep := func(initialized bool) {
			GinkgoHelper()
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			oldEgress, _ := env.expectPaired(ctx, peer, vni)

			env.stopMetalnet()
			env.restartDpservice()
			if initialized {
				Eventually(func() error {
					_, err := dpdkClient.Initialize(ctx)
					return err
				}, encTimeout, encPolling).Should(Succeed())
			}
			env.rekey(ctx, vni)
			Eventually(func(g Gomega) {
				g.Expect(env.clientStatus(ctx, g).Pairs).To(ContainElement(HaveField("Waiting", Not(Equal(mlsbond.WaitingNothing)))))
			}, encTimeout, encPolling).Should(Succeed())

			env.proxy = newLateStepProxy(env.mlsbondClient)
			env.startMetalnet()

			Eventually(func(g Gomega) {
				egress, _ := env.pairedWith(ctx, g, peer, vni)
				g.Expect(egress.Spec.Key).NotTo(Equal(oldEgress.Spec.Key))
			}, encTimeout, encPolling).Should(Succeed())
			eventuallyReady()
			Consistently(func(g Gomega) {
				env.pairedWith(ctx, g, peer, vni)
			}, encConsistent, encPolling).Should(Succeed())
		}

		It("carries out no step sent before it reported its new dpservice", func() {
			lateStep(false)
		})

		It("carries out no step sent before it reported that it lost its associations", func() {
			lateStep(true)
		})

		It("is Pending from the moment metalnet starts without its dpservice", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()

			env.stopMetalnet()
			env.stopDpservice()
			env.startMetalnetExpectingExit()
			Expect(env.entry(ctx, network)).To(haveState(metalnetv1alpha1.EncryptionStatePending))

			env.startDpservice()
			env.startMetalnet()
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)
		})

		It("changes nothing when metalnet restarts", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			egress, ingress := env.expectPaired(ctx, peer, vni)
			held := peer.orch.held()

			env.restartMetalnet()
			eventuallyReady()
			Consistently(func(g Gomega) {
				g.Expect(env.installed(ctx, vni)()).To(ConsistOf(egress.Spi, ingress.Spi))
				g.Expect(peer.orch.held()).To(Equal(held))
			}, encConsistent, encPolling).Should(Succeed())
		})

		It("keeps metalnet's subscriptions when the mlsbond client restarts after it", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)

			env.restartMLSBondClient()
			Eventually(func(g Gomega) {
				st := env.clientStatus(ctx, g)
				g.Expect(st.VNIs).To(ContainElement(vni))
				g.Expect(st.Pairs).To(ContainElement(HaveField("Waiting", mlsbond.WaitingNothing)))
			}, encTimeout, encPolling).Should(Succeed())
			Eventually(func(g Gomega) { env.pairedWith(ctx, g, peer, vni) }, encTimeout, encPolling).Should(Succeed())
			Expect(env.entry(ctx, network)).To(haveState(metalnetv1alpha1.EncryptionStateReady))
		})

		It("has its associations replaced, with nothing left behind, when metalnet and the mlsbond client restart together", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			egress, ingress := env.expectPaired(ctx, peer, vni)

			env.stopMetalnet()
			env.restartMLSBondClient()
			env.startMetalnet()

			Eventually(func(g Gomega) {
				e, i := env.pairedWith(ctx, g, peer, vni)
				g.Expect(e.Spi).NotTo(Equal(egress.Spi))
				g.Expect(i.Spi).NotTo(Equal(ingress.Spi))
				g.Expect(env.installed(ctx, vni)()).To(HaveLen(2), "nothing is left behind")
			}, 3*encTimeout, encPolling).Should(Succeed())
			eventuallyReady()
		})

		It("changes no status on a rekey", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			_, ingress := env.expectPaired(ctx, peer, vni)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
			version := network.ResourceVersion

			env.rekey(ctx, vni)
			Eventually(func(g Gomega) {
				_, i := env.pairedWith(ctx, g, peer, vni)
				g.Expect(i.Spi).NotTo(Equal(ingress.Spi))
			}, encTimeout, encPolling).Should(Succeed())

			Consistently(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
				g.Expect(network.ResourceVersion).To(Equal(version))
			}, encConsistent, encPolling).Should(Succeed())
		})

		It("changes no status when a host joins a VNI that is Ready", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
			version := network.ResourceVersion

			second := env.newPeer("peer2", "fc00:3::/64")
			second.subscribe(vni)
			Eventually(func(g Gomega) { env.pairedWith(ctx, g, second, vni) }, encTimeout, encPolling).Should(Succeed())

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
			Expect(network.ResourceVersion).To(Equal(version))
		})

		It("reports a failing install in message while another peer keeps it Ready, and clears it when its retry succeeds", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)

			By("using up all of dpservice's slots")
			fillers := env.fillSecurityAssociations(ctx)
			DeferCleanup(func() { env.releaseSecurityAssociations(ctx, fillers) })

			second := env.newPeer("peer2", "fc00:3::/64")
			second.subscribe(vni)
			Eventually(func(g Gomega) {
				entry := env.entry(ctx, network)
				g.Expect(entry).NotTo(BeNil())
				g.Expect(entry.State).To(Equal(metalnetv1alpha1.EncryptionStateReady))
				g.Expect(entry.Message).To(ContainSubstring("fc00:3::"))
			}, encTimeout, encPolling).Should(Succeed())

			By("freeing them")
			env.releaseSecurityAssociations(ctx, fillers)
			Eventually(func(g Gomega) {
				entry := env.entry(ctx, network)
				g.Expect(entry).NotTo(BeNil())
				g.Expect(entry.State).To(Equal(metalnetv1alpha1.EncryptionStateReady))
				g.Expect(entry.Message).To(BeEmpty())
			}, 2*encTimeout, encPolling).Should(Succeed())
			env.expectPaired(ctx, second, vni)
		})

		It("only touches its own entry", func() {
			other := metalnetapply.Network(network.Name, network.Namespace).WithStatus(metalnetapply.NetworkStatus().WithEncryption(
				metalnetapply.NetworkEncryptionStatus().WithNodeName("other-node").WithState(metalnetv1alpha1.EncryptionStateReady).WithMessage("mine")))
			Expect(k8sClient.Status().Apply(ctx, other, client.FieldOwner("metalnet-other-node"))).To(Succeed())

			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			expectOther := func() {
				GinkgoHelper()
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
				Expect(network.Status.Encryption).To(ContainElement(metalnetv1alpha1.NetworkEncryptionStatus{
					NodeName: "other-node", State: metalnetv1alpha1.EncryptionStateReady, Message: "mine",
				}))
			}
			expectOther()

			setNetworkEncrypt(network, false)
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(BeNil())
			expectOther()
		})

		It("reconciles nothing because of a status write", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)
			time.Sleep(encConsistent)

			before := env.reconciles()
			other := metalnetapply.Network(network.Name, network.Namespace).WithStatus(metalnetapply.NetworkStatus().WithEncryption(
				metalnetapply.NetworkEncryptionStatus().WithNodeName("other-node").WithState(metalnetv1alpha1.EncryptionStatePending)))
			Expect(k8sClient.Status().Apply(ctx, other, client.FieldOwner("metalnet-other-node"))).To(Succeed())
			Consistently(env.reconciles, encConsistent, encPolling).Should(Equal(before))

			By("while a change of the spec still reaches the interfaces")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), network)).To(Succeed())
			base := network.DeepCopy()
			network.Spec.PeeredIDs = []int32{3199}
			Expect(k8sClient.Patch(ctx, network, client.MergeFrom(base))).To(Succeed())
			Eventually(func() float64 { return env.reconciles()["networkinterface"] }, encTimeout, encPolling).Should(BeNumerically(">", before["networkinterface"]))
		})

		It("reports no failure for a pair that ended", func() {
			peer := env.newPeer("peer1", "fc00:2::/64")
			peer.subscribe(vni)
			eventuallyReady()
			env.expectPaired(ctx, peer, vni)

			By("a host joining that cannot get its associations installed")
			fillers := env.fillSecurityAssociations(ctx)
			DeferCleanup(func() { env.releaseSecurityAssociations(ctx, fillers) })
			second := env.newPeer("peer2", "fc00:3::/64")
			second.subscribe(vni)
			Eventually(func(g Gomega) {
				entry := env.entry(ctx, network)
				g.Expect(entry).NotTo(BeNil())
				g.Expect(entry.Message).To(ContainSubstring("fc00:3::"))
			}, encTimeout, encPolling).Should(Succeed())

			By("that host leaving again, with nothing installed for it")
			second.unsubscribe(vni)
			Eventually(func(g Gomega) {
				entry := env.entry(ctx, network)
				g.Expect(entry).To(haveState(metalnetv1alpha1.EncryptionStateReady))
				g.Expect(entry.Message).To(BeEmpty())
			}, encTimeout, encPolling).Should(Succeed())
		})

		It("keeps starting with a debug key file it cannot read", func() {
			env.stopMetalnet()
			Expect(os.MkdirAll(filepath.Dir(env.keyFile), 0o700)).To(Succeed())
			Expect(os.WriteFile(env.keyFile, []byte("{half a fi"), 0o600)).To(Succeed())
			env.startMetalnet()
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStatePending))
		})

		It("touches nothing without an mlsbond client", func() {
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStatePending))
			before := env.entry(ctx, network)
			env.stopMetalnet()
			env.mlsbondClient = ""
			env.startMetalnet()
			Consistently(env.entryGetter(ctx, network), encConsistent, encPolling).Should(Equal(before))
		})
	})

	It("writes no keys anywhere without the debug flag", func() {
		env.startMLSBond()
		env.keyFile = ""
		env.startMetalnet()
		network := newNetwork(3150, true)
		newInterface(network, "vm", "10.31.5.1", false)
		peer := env.newPeer("peer1", "fc00:2::/64")
		peer.subscribe(uint32(network.Spec.ID))
		Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStateReady))

		key := hex.EncodeToString(peer.orch.anyKey())
		Expect(filepath.WalkDir(env.dir, func(path string, d os.DirEntry, err error) error {
			Expect(err).NotTo(HaveOccurred())
			if !d.IsDir() {
				data, err := os.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				Expect(strings.ToLower(string(data))).NotTo(ContainSubstring(key), path)
			}
			return nil
		})).To(Succeed())
	})

	Describe("of a NetworkInterface", func() {
		BeforeEach(func() {
			env.startMLSBond()
			env.startMetalnet()
		})

		dataplaneFlag := func(nic *metalnetv1alpha1.NetworkInterface) func(g Gomega) bool {
			return func(g Gomega) bool {
				iface, err := dpdkClient.GetInterface(ctx, string(nic.UID))
				g.Expect(err).NotTo(HaveOccurred())
				return iface.Spec.Encrypt
			}
		}

		encryptionStatus := func(nic *metalnetv1alpha1.NetworkInterface) func(g Gomega) metalnetv1alpha1.EncryptionState {
			return func(g Gomega) metalnetv1alpha1.EncryptionState {
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(nic), nic)).To(Succeed())
				return nic.Status.Encryption
			}
		}

		It("creates the interface with its flag, and switches it live, with the status following dpservice", func() {
			network := newNetwork(3200, false)
			nic := newInterface(network, "vm", "10.32.0.1", true)
			Eventually(encryptionStatus(nic), encTimeout, encPolling).Should(Equal(metalnetv1alpha1.EncryptionStateReady))
			Eventually(dataplaneFlag(nic), encTimeout, encPolling).Should(BeTrue())

			setInterfaceEncrypt(nic, false)
			Eventually(dataplaneFlag(nic), encTimeout, encPolling).Should(BeFalse())
			Eventually(encryptionStatus(nic), encTimeout, encPolling).Should(BeEmpty())

			setInterfaceEncrypt(nic, true)
			Eventually(dataplaneFlag(nic), encTimeout, encPolling).Should(BeTrue())
			Eventually(encryptionStatus(nic), encTimeout, encPolling).Should(Equal(metalnetv1alpha1.EncryptionStateReady))
		})

		It("sends in the clear without encrypt, drops with encrypt and no keys, and sends ESP with keys", func() {
			network := newNetwork(3210, false)
			vni := uint32(network.Spec.ID)
			nic := newInterface(network, "vm", "10.32.1.1", false)
			peer := env.newPeer("peer1", "fc00:2::/64")
			env.routeToPeer(ctx, vni, "10.32.1.2", peer)
			tap := nic.Status.TAPDevice.Name

			Expect(env.sendAndCapture(tap, "10.32.1.1", "10.32.1.2")).To(Equal(captured{cleartext: true}))

			By("the interface encrypting on a Network without encrypt")
			setInterfaceEncrypt(nic, true)
			Eventually(encryptionStatus(nic), encTimeout, encPolling).Should(Equal(metalnetv1alpha1.EncryptionStateReady))
			Expect(env.sendAndCapture(tap, "10.32.1.1", "10.32.1.2")).To(Equal(captured{}))

			By("the Network getting keys")
			setNetworkEncrypt(network, true)
			peer.subscribe(vni)
			Eventually(env.entryGetter(ctx, network), encTimeout, encPolling).Should(haveState(metalnetv1alpha1.EncryptionStateReady))
			env.expectPaired(ctx, peer, vni)
			Expect(env.sendAndCapture(tap, "10.32.1.1", "10.32.1.2")).To(Equal(captured{esp: true}))

			By("the Network losing its keys under the encrypting interface")
			setNetworkEncrypt(network, false)
			Eventually(env.installed(ctx, vni), encTimeout, encPolling).Should(BeEmpty())
			Expect(env.sendAndCapture(tap, "10.32.1.1", "10.32.1.2")).To(Equal(captured{}))
		})
	})
})

// haveState matches an encryption status entry in a state.
func haveState(state metalnetv1alpha1.EncryptionState) gomegatypes.GomegaMatcher {
	return And(Not(BeNil()), HaveField("State", state))
}

// encryptionEnv is one host and its surroundings, for one spec.
type encryptionEnv struct {
	dir           string
	metalnetDir   string
	keyFile       string
	kubeconfig    string
	mlsbondServer string
	mlsbondAdmin  mlsbondpb.AdminClient
	mlsbondClient string
	clientProc    *process
	// what metalnet reaches its mlsbond client through, if not directly
	proxy       *lateStepProxy
	metalnet    *process
	metricsAddr string
	healthAddr  string
	processes   []*process
}

func newEncryptionEnv() *encryptionEnv {
	dir := GinkgoT().TempDir()
	user, err := testEnv.AddUser(envtest.User{Name: "metalnet", Groups: []string{"system:masters"}}, nil)
	Expect(err).NotTo(HaveOccurred())
	kubeconfig, err := user.KubeConfig()
	Expect(err).NotTo(HaveOccurred())
	path := filepath.Join(dir, "kubeconfig")
	Expect(os.WriteFile(path, kubeconfig, 0o600)).To(Succeed())
	return &encryptionEnv{
		dir:         dir,
		metalnetDir: filepath.Join(dir, "metalnet"),
		keyFile:     filepath.Join(dir, "keys", "keys.json"),
		kubeconfig:  path,
	}
}

// cleanUp leaves dpservice as it was: metalnet deletes what the spec created, with mlsbond still there
// for the Security Associations to go through it. The specs share the dpservice, so this comes first.
func (e *encryptionEnv) cleanUp(ctx context.Context, namespace string) {
	GinkgoHelper()
	if e.metalnet != nil && !e.metalnet.running() {
		e.startMetalnet()
	}
	Expect(k8sClient.DeleteAllOf(ctx, &metalnetv1alpha1.NetworkInterface{}, client.InNamespace(namespace))).To(Succeed())
	Expect(k8sClient.DeleteAllOf(ctx, &metalnetv1alpha1.Network{}, client.InNamespace(namespace))).To(Succeed())
	if e.metalnet != nil {
		Eventually(func(g Gomega) {
			nics := &metalnetv1alpha1.NetworkInterfaceList{}
			g.Expect(k8sClient.List(ctx, nics, client.InNamespace(namespace))).To(Succeed())
			g.Expect(nics.Items).To(BeEmpty())
			networks := &metalnetv1alpha1.NetworkList{}
			g.Expect(k8sClient.List(ctx, networks, client.InNamespace(namespace))).To(Succeed())
			g.Expect(networks.Items).To(BeEmpty())
			sas, err := dpdkClient.ListSecurityAssociations(ctx)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(sas.Items).To(BeEmpty())
		}, encTimeout, encPolling).Should(Succeed())
	}
	for _, p := range e.processes {
		p.kill()
	}
	if e.proxy != nil {
		e.proxy.stop()
	}
}

func freeTCPAddr() string {
	GinkgoHelper()
	lis, err := net.Listen("tcp", "[::1]:0")
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = lis.Close() }()
	return lis.Addr().String()
}

// process is a binary running, its output going to the Ginkgo log.
type process struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (e *encryptionEnv) startProcess(name string, env []string, bin string, args ...string) *process {
	GinkgoHelper()
	p := &process{done: make(chan struct{})}
	e.processes = append(e.processes, p)
	p.cmd = exec.Command(bin, args...)
	p.cmd.Env = append(os.Environ(), env...)
	out, err := p.cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	p.cmd.Stderr = p.cmd.Stdout
	Expect(p.cmd.Start()).To(Succeed())
	go func() {
		defer close(p.done)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(nil, 1024*1024)
		for scanner.Scan() {
			_, _ = fmt.Fprintf(GinkgoWriter, "%s %s: %s\n", time.Now().Format("15:04:05.000"), name, scanner.Text())
		}
		_, _ = io.Copy(io.Discard, out)
		_ = p.cmd.Wait()
	}()
	return p
}

func (p *process) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *process) kill() {
	if p.running() {
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		<-p.done
	}
}

// term asks the process to stop, as kubelet does.
func (p *process) term() {
	GinkgoHelper()
	Expect(p.cmd.Process.Signal(syscall.SIGTERM)).To(Succeed())
	Eventually(p.done, encTimeout, encPolling).Should(BeClosed())
}

func listening(addr string) {
	GinkgoHelper()
	Eventually(func() error {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}, encTimeout, encPolling).Should(Succeed(), "nothing listens at %s", addr)
}

func (e *encryptionEnv) startMLSBond() {
	GinkgoHelper()
	e.mlsbondServer = freeTCPAddr()
	admin := freeTCPAddr()
	e.startProcess("mlsbond-server", nil, filepath.Join(os.Getenv("MLSBOND_BIN"), "mlsbond-server"),
		"--listen", e.mlsbondServer, "--admin-listen", admin, "--removal-grace", "1", "--commit-delay-ms", "50")
	listening(e.mlsbondServer)
	listening(admin)
	conn, err := grpc.NewClient(admin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(conn.Close)
	e.mlsbondAdmin = mlsbondpb.NewAdminClient(conn)

	e.mlsbondClient = freeTCPAddr()
	e.startMLSBondClient()
}

func (e *encryptionEnv) startMLSBondClient() {
	GinkgoHelper()
	e.clientProc = e.startProcess("mlsbond-client", nil, filepath.Join(os.Getenv("MLSBOND_BIN"), "mlsbond-client"),
		"--listen", e.mlsbondClient, "--server", e.mlsbondServer, "--stale-pairs-after", "5")
	listening(e.mlsbondClient)
}

func (e *encryptionEnv) restartMLSBondClient() {
	GinkgoHelper()
	e.clientProc.kill()
	e.startMLSBondClient()
}

func (e *encryptionEnv) metalnetArgs() []string {
	e.healthAddr = freeTCPAddr()
	e.metricsAddr = freeTCPAddr()
	args := []string{
		"--tapdevice-mod",
		"--node-name=" + encNode,
		"--dp-service-address=127.0.0.1:1337",
		"--metalbond-peer=[::1]:4711",
		"--router-address=fc00:1::ffff",
		"--enable-ipv6",
		"--metalnet-dir=" + e.metalnetDir,
		"--health-probe-bind-address=" + e.healthAddr,
		"--metrics-bind-address=" + e.metricsAddr,
		"--metrics-secure=false",
		"--zap-log-level=2",
	}
	if e.proxy != nil {
		args = append(args, "--mlsbond-client="+e.proxy.address)
	} else if e.mlsbondClient != "" {
		args = append(args, "--mlsbond-client="+e.mlsbondClient)
	}
	if e.keyFile != "" {
		args = append(args, "--debug-key-file="+e.keyFile)
	}
	return args
}

func (e *encryptionEnv) health() (int, error) {
	res, err := http.Get("http://" + e.healthAddr + "/healthz")
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode, nil
}

func (e *encryptionEnv) startMetalnet() {
	GinkgoHelper()
	e.metalnet = e.startProcess("metalnet", []string{"KUBECONFIG=" + e.kubeconfig}, os.Getenv("METALNET_BIN"), e.metalnetArgs()...)
	Eventually(func() (int, error) {
		if !e.metalnet.running() {
			return 0, StopTrying("metalnet exited")
		}
		return e.health()
	}, encTimeout, encPolling).Should(Equal(http.StatusOK))
}

// startMetalnetExpectingExit starts a metalnet that is to give up, as it does without dpservice.
func (e *encryptionEnv) startMetalnetExpectingExit() {
	GinkgoHelper()
	e.metalnet = e.startProcess("metalnet", []string{"KUBECONFIG=" + e.kubeconfig}, os.Getenv("METALNET_BIN"), e.metalnetArgs()...)
	Eventually(e.metalnet.done, encTimeout, encPolling).Should(BeClosed())
}

func (e *encryptionEnv) stopMetalnet() {
	GinkgoHelper()
	if e.metalnet.running() {
		e.metalnet.term()
	}
}

func (e *encryptionEnv) restartMetalnet() {
	GinkgoHelper()
	e.stopMetalnet()
	e.startMetalnet()
}

func (e *encryptionEnv) expectUnhealthy() {
	GinkgoHelper()
	Eventually(e.health, encTimeout, encPolling).ShouldNot(Equal(http.StatusOK))
}

func runScript(env string) {
	GinkgoHelper()
	fields := strings.Fields(os.Getenv(env))
	out, err := exec.Command(fields[0], fields[1:]...).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))
}

func (e *encryptionEnv) restartDpservice() {
	GinkgoHelper()
	runScript("DPSERVICE_RESTART_CMD")
}

func (e *encryptionEnv) stopDpservice() {
	GinkgoHelper()
	runScript("DPSERVICE_STOP_CMD")
}

func (e *encryptionEnv) startDpservice() {
	GinkgoHelper()
	runScript("DPSERVICE_START_CMD")
}

func (e *encryptionEnv) entry(ctx context.Context, network *metalnetv1alpha1.Network) *metalnetv1alpha1.NetworkEncryptionStatus {
	GinkgoHelper()
	current := &metalnetv1alpha1.Network{}
	Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(network), current)).To(Succeed())
	for i := range current.Status.Encryption {
		if current.Status.Encryption[i].NodeName == encNode {
			return &current.Status.Encryption[i]
		}
	}
	return nil
}

func (e *encryptionEnv) entryGetter(ctx context.Context, network *metalnetv1alpha1.Network) func() *metalnetv1alpha1.NetworkEncryptionStatus {
	return func() *metalnetv1alpha1.NetworkEncryptionStatus {
		return e.entry(ctx, network)
	}
}

// installed returns what dpservice holds in vni, by SPI.
func (e *encryptionEnv) installed(ctx context.Context, vni uint32) func() []uint32 {
	return func() []uint32 {
		GinkgoHelper()
		list, err := dpdkClient.ListSecurityAssociations(ctx)
		Expect(err).NotTo(HaveOccurred())
		spis := []uint32{}
		for _, sa := range list.Items {
			if sa.Vni == vni {
				spis = append(spis, sa.Spi)
			}
		}
		return spis
	}
}

// pairedWith checks that dpservice and the peer hold the pair's two Security Associations, with the
// same keys, and returns dpservice's egress and ingress.
func (e *encryptionEnv) pairedWith(ctx context.Context, g Gomega, peer *peerHost, vni uint32) (egress, ingress *dpdk.SecurityAssociation) {
	GinkgoHelper()
	local := netip.MustParsePrefix(localPrefix).Addr()
	remote := peer.prefix.Addr()
	list, err := dpdkClient.ListSecurityAssociations(ctx)
	g.Expect(err).NotTo(HaveOccurred())
	for i := range list.Items {
		sa := &list.Items[i]
		if sa.Vni != vni {
			continue
		}
		switch {
		case strings.EqualFold(sa.Direction, "egress") && *sa.DstUnderlay == remote:
			g.Expect(egress).To(BeNil(), "one egress towards the peer")
			egress, err = dpdkClient.GetSecurityAssociation(ctx, &sa.SecurityAssociationMeta)
		case strings.EqualFold(sa.Direction, "ingress") && *sa.SrcUnderlay == remote:
			g.Expect(ingress).To(BeNil(), "one ingress from the peer")
			ingress, err = dpdkClient.GetSecurityAssociation(ctx, &sa.SecurityAssociationMeta)
		}
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(egress).NotTo(BeNil(), "an egress towards %s", remote)
	g.Expect(ingress).NotTo(BeNil(), "an ingress from %s", remote)

	theirs := peer.orch.held()
	peerIngress, ok := theirs[mlsbond.SecurityAssociationID{VNI: vni, SPI: egress.Spi, Direction: mlsbond.Ingress, Src: local, Dst: remote}]
	g.Expect(ok).To(BeTrue(), "the peer's ingress for egress spi %d", egress.Spi)
	g.Expect(hex.EncodeToString(peerIngress.Key)).To(Equal(strings.ToLower(egress.Spec.Key)))
	g.Expect(hex.EncodeToString(peerIngress.Salt)).To(Equal(strings.ToLower(egress.Spec.Salt)))
	peerEgress, ok := theirs[mlsbond.SecurityAssociationID{VNI: vni, SPI: ingress.Spi, Direction: mlsbond.Egress, Src: remote, Dst: local}]
	g.Expect(ok).To(BeTrue(), "the peer's egress for ingress spi %d", ingress.Spi)
	g.Expect(hex.EncodeToString(peerEgress.Key)).To(Equal(strings.ToLower(ingress.Spec.Key)))
	return egress, ingress
}

func (e *encryptionEnv) expectPaired(ctx context.Context, peer *peerHost, vni uint32) (egress, ingress *dpdk.SecurityAssociation) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		egress, ingress = e.pairedWith(ctx, g, peer, vni)
	}, encTimeout, encPolling).Should(Succeed())
	return egress, ingress
}

func (e *encryptionEnv) rekey(ctx context.Context, vni uint32) {
	GinkgoHelper()
	_, err := e.mlsbondAdmin.Rekey(ctx, &mlsbondpb.RekeyRequest{Vni: vni})
	Expect(err).NotTo(HaveOccurred())
}

// clientStatus asks the host's mlsbond client directly.
func (e *encryptionEnv) clientStatus(ctx context.Context, g Gomega) *mlsbond.Status {
	GinkgoHelper()
	conn, err := grpc.NewClient(e.mlsbondClient, grpc.WithTransportCredentials(insecure.NewCredentials()))
	g.Expect(err).NotTo(HaveOccurred())
	defer func() { _ = conn.Close() }()
	res, err := mlsbondpb.NewClientAPIClient(conn).Status(ctx, &mlsbondpb.StatusRequest{})
	g.Expect(err).NotTo(HaveOccurred())
	st := &mlsbond.Status{VNIs: res.Vnis}
	for _, p := range res.Pairs {
		st.Pairs = append(st.Pairs, mlsbond.PairStatus{VNI: p.Vni, Waiting: mlsbond.Waiting(p.Waiting)})
	}
	return st
}

func (e *encryptionEnv) keyFileEntries() []map[string]any {
	GinkgoHelper()
	data, err := os.ReadFile(e.keyFile)
	if os.IsNotExist(err) {
		return nil
	}
	Expect(err).NotTo(HaveOccurred())
	var content struct {
		Associations []map[string]any `json:"associations"`
	}
	Expect(json.Unmarshal(data, &content)).To(Succeed())
	return content.Associations
}

func (e *encryptionEnv) keyFileSPIs() []uint32 {
	GinkgoHelper()
	spis := []uint32{}
	for _, entry := range e.keyFileEntries() {
		spis = append(spis, uint32(entry["spi"].(float64)))
	}
	return spis
}

func (e *encryptionEnv) keyFileEntry(spi uint32) map[string]any {
	GinkgoHelper()
	for _, entry := range e.keyFileEntries() {
		if uint32(entry["spi"].(float64)) == spi {
			return entry
		}
	}
	return nil
}

var reconcileMetric = regexp.MustCompile(`^controller_runtime_reconcile_total\{controller="(\w+)",result="\w+"\} (\d+)`)

// reconciles is what metalnet's metrics say it has reconciled so far, per controller.
func (e *encryptionEnv) reconciles() map[string]float64 {
	GinkgoHelper()
	res, err := http.Get("http://" + e.metricsAddr + "/metrics")
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = res.Body.Close() }()
	counts := map[string]float64{}
	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(nil, 1024*1024)
	for scanner.Scan() {
		if m := reconcileMetric.FindStringSubmatch(scanner.Text()); m != nil {
			n, err := strconv.ParseFloat(m[2], 64)
			Expect(err).NotTo(HaveOccurred())
			counts[m[1]] += n
		}
	}
	return counts
}

// fillSecurityAssociations uses up dpservice's slots with associations of a VNI of their own.
func (e *encryptionEnv) fillSecurityAssociations(ctx context.Context) []dpdk.SecurityAssociationMeta {
	GinkgoHelper()
	src, dst := netip.MustParseAddr("fc00:ff::"), netip.MustParsePrefix(localPrefix).Addr()
	var fillers []dpdk.SecurityAssociationMeta
	for spi := uint32(1000); ; spi++ {
		meta := dpdk.SecurityAssociationMeta{Vni: 3999, Spi: spi, Direction: "ingress", SrcUnderlay: &src, DstUnderlay: &dst}
		_, err := dpdkClient.CreateSecurityAssociation(ctx, &dpdk.SecurityAssociation{
			SecurityAssociationMeta: meta,
			Spec: dpdk.SecurityAssociationSpec{
				Algorithm:    "aes-256-gcm",
				Key:          strings.Repeat("ab", 32),
				Salt:         strings.Repeat("cd", 4),
				ReplayWindow: 64,
				Esn:          true,
			},
		})
		if err != nil {
			Expect(fillers).NotTo(BeEmpty(), err.Error())
			return fillers
		}
		fillers = append(fillers, meta)
		Expect(len(fillers)).To(BeNumerically("<=", 64))
	}
}

func (e *encryptionEnv) releaseSecurityAssociations(ctx context.Context, fillers []dpdk.SecurityAssociationMeta) {
	GinkgoHelper()
	for i := range fillers {
		_, err := dpdkClient.DeleteSecurityAssociation(ctx, &fillers[i], dpdkerrors.Ignore(dpdkerrors.SA_NOT_FOUND))
		Expect(err).NotTo(HaveOccurred())
	}
}

// routeToPeer routes an overlay address to a simulated host, as metalbond would.
func (e *encryptionEnv) routeToPeer(ctx context.Context, vni uint32, ip string, peer *peerHost) {
	GinkgoHelper()
	prefix := netip.PrefixFrom(netip.MustParseAddr(ip), 32)
	nextHop := peer.prefix.Addr().Next()
	Expect(dpdkClient.CreateRoute(ctx, &dpdk.Route{
		RouteMeta: dpdk.RouteMeta{VNI: vni},
		Spec:      dpdk.RouteSpec{Prefix: &prefix, NextHop: &dpdk.RouteNextHop{VNI: 0, IP: &nextHop}},
	})).Error().NotTo(HaveOccurred())
}

// captured is what left the physical ports.
type captured struct {
	cleartext bool
	esp       bool
}

const (
	ipProtoIPIP = 4
	ipProtoESP  = 50
	pfMAC       = "22:22:22:22:22:00"
)

// sendAndCapture sends a VM's UDP packets to dst and reports how they leave dpservice.
func (e *encryptionEnv) sendAndCapture(tap, src, dst string) captured {
	GinkgoHelper()
	res := captured{}
	var mtx sync.Mutex
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, pf := range []string{"dtap0", "dtap1"} {
		fd := rawSocket(pf, unix.ETH_P_IPV6)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = unix.Close(fd) }()
			buf := make([]byte, 2048)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, _, err := unix.Recvfrom(fd, buf, 0)
				if err != nil || n < 14+40 {
					continue
				}
				mtx.Lock()
				switch buf[14+6] {
				case ipProtoIPIP:
					res.cleartext = true
				case ipProtoESP:
					res.esp = true
				}
				mtx.Unlock()
			}
		}()
	}

	fd := rawSocket(tap, unix.ETH_P_ALL)
	defer func() { _ = unix.Close(fd) }()
	vmMAC, err := net.ParseMAC("66:66:66:66:66:0" + tap[len(tap)-1:])
	Expect(err).NotTo(HaveOccurred())
	frame := udpFrame(vmMAC, netip.MustParseAddr(src), netip.MustParseAddr(dst))
	for range 5 {
		Expect(unix.Write(fd, frame)).Error().NotTo(HaveOccurred())
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
	mtx.Lock()
	defer mtx.Unlock()
	return res
}

// rawSocket opens a socket on an interface, whose reads give up after a while.
func rawSocket(iface string, proto uint16) int {
	GinkgoHelper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(proto)))
	Expect(err).NotTo(HaveOccurred())
	link, err := net.InterfaceByName(iface)
	Expect(err).NotTo(HaveOccurred())
	Expect(unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: link.Index})).To(Succeed())
	Expect(unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000})).To(Succeed())
	return fd
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func udpFrame(srcMAC net.HardwareAddr, src, dst netip.Addr) []byte {
	GinkgoHelper()
	dstMAC, err := net.ParseMAC(pfMAC)
	Expect(err).NotTo(HaveOccurred())
	payload := []byte("encryption-spec")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 4000)
	binary.BigEndian.PutUint16(udp[2:], 4001)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(udp)))
	ip[8] = 64
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	var sum uint32
	for i := 0; i < len(ip); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum+sum>>16))
	frame := append(append(append(append([]byte{}, dstMAC...), srcMAC...), 0x08, 0x00), ip...)
	return append(frame, udp...)
}

// peerHost simulates another host of a VNI group: an mlsbond client with an orchestrator that holds
// its Security Associations in memory.
type peerHost struct {
	prefix netip.Prefix
	conn   *mlsbond.Conn
	orch   *fakeOrchestrator
}

func (e *encryptionEnv) newPeer(name, prefix string) *peerHost {
	GinkgoHelper()
	p := &peerHost{prefix: netip.MustParsePrefix(prefix), orch: &fakeOrchestrator{sas: map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation{}}}
	addr := freeTCPAddr()
	e.startProcess(name, nil, filepath.Join(os.Getenv("MLSBOND_BIN"), "mlsbond-client"),
		"--listen", addr, "--server", e.mlsbondServer, "--stale-pairs-after", "5")
	listening(addr)
	conn, err := mlsbond.Connect(context.Background(), addr, name, p.prefix, p.orch)
	Expect(err).NotTo(HaveOccurred())
	p.conn = conn
	DeferCleanup(func() { _ = conn.Close() })
	return p
}

func (p *peerHost) subscribe(vni uint32) {
	GinkgoHelper()
	Expect(p.conn.Subscribe(context.Background(), vni)).To(Succeed())
}

func (p *peerHost) unsubscribe(vni uint32) {
	GinkgoHelper()
	Expect(p.conn.Unsubscribe(context.Background(), vni)).To(Succeed())
}

type fakeOrchestrator struct {
	mtx sync.Mutex
	sas map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation
}

func (f *fakeOrchestrator) AddSecurityAssociation(sa mlsbond.SecurityAssociation) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.sas[sa.ID] = sa
	return nil
}

func (f *fakeOrchestrator) UpdateSecurityAssociation(old mlsbond.SecurityAssociationID, sa mlsbond.SecurityAssociation) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	delete(f.sas, old)
	f.sas[sa.ID] = sa
	return nil
}

func (f *fakeOrchestrator) RemoveSecurityAssociation(id mlsbond.SecurityAssociationID) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	delete(f.sas, id)
	return nil
}

func (f *fakeOrchestrator) SecurityAssociations() []mlsbond.SecurityAssociationID {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	ids := make([]mlsbond.SecurityAssociationID, 0, len(f.sas))
	for id := range f.sas {
		ids = append(ids, id)
	}
	return ids
}

func (f *fakeOrchestrator) held() map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return maps.Clone(f.sas)
}

func (f *fakeOrchestrator) anyKey() []byte {
	GinkgoHelper()
	Eventually(f.held, encTimeout, encPolling).ShouldNot(BeEmpty())
	for _, sa := range f.held() {
		return sa.Key
	}
	return nil
}
