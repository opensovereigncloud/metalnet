// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	goflag "flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jaypipes/ghw"
	flag "github.com/spf13/pflag"

	metalnetclient "github.com/ironcore-dev/metalnet/client"
	"github.com/ironcore-dev/metalnet/internal"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/ironcore-dev/metalnet/control"
	"github.com/ironcore-dev/metalnet/metalbond"
	"github.com/ironcore-dev/metalnet/netfns"
	"github.com/ironcore-dev/metalnet/sysfs"

	dpdk "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkclient "github.com/ironcore-dev/dpservice/go/dpservice-go/client"
	dpdkproto "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"
	mb "github.com/ironcore-dev/metalbond"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/hashicorp/go-version"
	networkingv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	"github.com/ironcore-dev/metalnet/controllers"
	//+kubebuilder:scaffold:imports
)

const dpserviceIPv6SupportVersionStr = "v0.3.1"

const bluefieldSuffix = "-bluefield"

var (
	scheme                      = runtime.NewScheme()
	setupLog                    = ctrl.Log.WithName("setup")
	hostName, _                 = os.Hostname()
	baseAddr                    = "0000:03:00.0"
	bluefieldHostDefaultBusAddr = "06"
	numOfVFs                    = 126
	pfToVfOffset                = 3
	buildVersion                string
	pendingRemovals             sync.Map
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(networkingv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var nodeName string
	var pfBaseAddr string
	var dpserviceAddr string
	var metalbondPeers []string
	var metalbondDebug bool
	var tapDeviceMod bool
	var bluefieldDetected = false
	var enableIPv6Support bool
	var routerAddress net.IP
	var publicVNI int
	var metalnetDir string
	var preferNetwork string
	var multiportEswitchMode bool
	var initAvailable []ghw.PCIAddress
	var defaultRouterAddr metalbond.DefaultRouterAddress
	var metalbondTxChanCapacity int
	var metalbondRxChanEventCapacity int
	var metalbondRxChanDataUpdateCapacity int
	var controlWebserverBindAddr string
	var podName, daemonSetName, namespace string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&nodeName, "node-name", hostName, "The node name to react to when reconciling network interfaces.")
	flag.StringVar(&pfBaseAddr, "pf-pci-base-addr", baseAddr, "Physical Function(pf) PCI base address used for VF address calculation")
	flag.StringVar(&dpserviceAddr, "dp-service-address", "127.0.0.1:1337", "The address of dpservice.")
	flag.StringSliceVar(&metalbondPeers, "metalbond-peer", nil, "The addresses of the metalbond peers.")
	flag.BoolVar(&metalbondDebug, "metalbond-debug", false, "Enable metalbond debug.")
	flag.BoolVar(&tapDeviceMod, "tapdevice-mod", false, "Enable TAP device support")
	flag.BoolVar(&enableIPv6Support, "enable-ipv6", false, "Enable IPv6 support")
	flag.IntVar(&publicVNI, "public-vni", 100, "Virtual network identifier used for public routing announcements.")
	flag.IPVar(&routerAddress, "router-address", net.IP{}, "The address of the next router.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&metalnetDir, "metalnet-dir", "/var/lib/metalnet", "Directory to store metalnet data at.")
	flag.StringVar(&preferNetwork, "prefer-network", "", "Prefer network routes (e.g. 2001:db8::1/52)")
	flag.IntVar(&metalbondTxChanCapacity, "metalbond-tx-chan-capacity", 100,
		"Specifies the maximum number of outgoing messages that can be queued before blocking; "+
			"controls the buffer size for outgoing messages.")
	flag.IntVar(&metalbondRxChanEventCapacity, "metalbond-rx-chan-event-capacity", 10,
		"Sets the buffer size for receiving HELLO and KEEPALIVE events; limits the number of "+
			"concurrent event messages that can be processed.")
	flag.IntVar(&metalbondRxChanDataUpdateCapacity, "metalbond-rx-chan-data-update-capacity", 100,
		"Defines the capacity for subscription and update messages (e.g., SUBSCRIBE, UNSUBSCRIBE, UPDATE); "+
			"manages the message queue for data updates and subscriptions.")
	flag.StringVar(&controlWebserverBindAddr, "control-webserver-bind-address", ":8082", "The address the control webserver binds to for reconciliation control.")
	flag.StringVar(&podName, "pod-name", "", "The name of the current pod.")
	flag.StringVar(&daemonSetName, "daemonset-name", "metalnet-controller-manager", "The name of the DaemonSet.")
	flag.StringVar(&namespace, "namespace", "metalnet-system", "The namespace of the DaemonSet.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(goflag.CommandLine)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Parse()

	if nodeName == "" || podName == "" {
		setupLog.Error(errors.New("node-name and pod-name are required"), "missing required flags")
		os.Exit(1)
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	if metalbondDebug {
		log.SetLevel(log.DebugLevel)
	}

	// Start the control webserver
	c := &control.ReconcileControl{}
	go control.StartControlWebserver(c, controlWebserverBindAddr)

	// Notify other DaemonSet-managed pods on this node to skip reconciliation
	if err := control.SkipReconcileOnOtherPods(nodeName, podName, daemonSetName, namespace); err != nil {
		setupLog.Error(err, "failed to notify other pods to skip reconciliation")
		os.Exit(1)
	}

	// Check if /var/lib/metalnet/mode exists and its content is "eswitch"
	modeFilePath := filepath.Join(metalnetDir, "mode")
	content, err := os.ReadFile(modeFilePath)
	if err == nil && string(content) == "eswitch" {
		multiportEswitchMode = true
	} else {
		multiportEswitchMode = false
	}

	// Log result for debugging
	log.Infof("Multiport Eswitch mode set to: %v", multiportEswitchMode)

	defaultRouterAddr.PublicVNI = uint32(publicVNI)
	defaultRouterAddr.SetBySubsciption = false

	sysFS, err := sysfs.NewDefaultFS()
	if err != nil {
		setupLog.Error(err, "error creating sysfs")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       fmt.Sprintf("%s.metalnet.onmetal.de", nodeName),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	claimStore, err := netfns.NewFileClaimStore(filepath.Join(metalnetDir, "netfns", "claims"), tapDeviceMod)
	if err != nil {
		setupLog.Error(err, "unable to create claim store")
		os.Exit(1)
	}

	if !tapDeviceMod {
		initAvailable, err = netfns.CollectVirtualFunctions(sysFS)
		if err != nil {
			setupLog.Error(err, "unable to collect virtual functions")
			os.Exit(1)
		}
		if len(initAvailable) == 0 {
			initAvailable, err = netfns.GenerateVirtualFunctions(pfBaseAddr, numOfVFs, pfToVfOffset)
			if err != nil {
				setupLog.Error(err, "unable to collect virtual functions with hard coded pf address", "PFAddress", pfBaseAddr)
				os.Exit(1)
			}
		}
	} else {
		initAvailable, err = netfns.CollectTAPFunctions([]string{"net_tap3", "net_tap4", "net_tap5"})
		if err != nil {
			setupLog.Error(err, "unable to collect TAP functions")
			os.Exit(1)
		}
	}

	netFnsManager, err := netfns.NewManager(claimStore, initAvailable)
	if err != nil {
		setupLog.Error(err, "unable to create netfns manager")
		os.Exit(1)
	}

	var preferredNetwork *net.IPNet
	if len(preferNetwork) > 0 {
		_, preferredNetwork, err = net.ParseCIDR(preferNetwork)
		if err != nil {
			log.Fatalf("invalid prefer network address: %s - %v", preferNetwork, err)
		}
	}

	// setup dpservice client
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	conn, err := grpc.NewClient(dpserviceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		setupLog.Error(err, "unable create dpdk client")
		os.Exit(1)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			setupLog.Error(err, "unable to close dpdk connection")
		}
	}()

	dpdkProtoClient := dpdkproto.NewDPDKonmetalClient(conn)
	dpdkClient := dpdkclient.NewClient(dpdkProtoClient)

	metalnetCache := internal.NewMetalnetCache(&logger)

	metalnetMBClient := metalbond.NewMetalnetClient(&logger, dpdkClient, metalnetCache, &defaultRouterAddr,
		metalbond.ClientOptions{
			IPv4Only:         true,
			PreferredNetwork: preferredNetwork,
		})

	config := mb.Config{
		KeepaliveInterval: 3,
	}

	mbInstance := mb.NewMetalBond(config, metalnetMBClient)
	metalbondRouteUtil := metalbond.NewMBRouteUtil(mbInstance)

	dpdkUUID, err := dpdkProtoClient.CheckInitialized(context.Background(), &dpdkproto.CheckInitializedRequest{})
	if err != nil {
		_, err = dpdkProtoClient.Initialize(context.Background(), &dpdkproto.InitializeRequest{})
		if err != nil {
			setupLog.Error(err, "dp-service can not be initialized")
			os.Exit(1)
		}

		dpdkUUID, err = dpdkProtoClient.CheckInitialized(context.Background(), &dpdkproto.CheckInitializedRequest{})
		if err != nil {
			setupLog.Error(err, "dp-service down")
			os.Exit(1)
		}
	}

	protoVersion, err := dpdkClient.GetVersion(ctx, &dpdk.Version{
		TypeMeta: dpdk.TypeMeta{Kind: dpdk.VersionKind},
		VersionMeta: dpdk.VersionMeta{
			ClientName:    fmt.Sprintf("metalnet-%s", hostName),
			ClientVersion: buildVersion,
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to get proto version")
	}
	setupLog.Info("protobuf versions",
		"dpserviceProtocol", protoVersion.Spec.ServiceProtocol,
		"dpserviceVersion", protoVersion.Spec.ServiceVersion,
		"metalnetName", protoVersion.ClientName,
		"metalnetProtocol", protoVersion.ClientProtocol,
		"metalnetVersion", protoVersion.ClientVersion)

	for _, metalbondPeer := range metalbondPeers {
		if err := mbInstance.AddPeer(metalbondPeer, "", metalbondTxChanCapacity, metalbondRxChanEventCapacity, metalbondRxChanDataUpdateCapacity); err != nil {
			setupLog.Error(err, "failed to add metalbond peer", "MetalbondPeer", metalbondPeer)
			os.Exit(1)
		}
	}

	metalnetMBClient.SetMetalBond(mbInstance)

	// Wait for first metalbond peer to connect
	deadline := time.Now().Add(10 * time.Second)
	for {
		connected := false
		for _, server := range metalbondPeers {
			state, err := mbInstance.PeerState(server)
			if err == nil && state == mb.ESTABLISHED {
				connected = true
				setupLog.Info("connected to metalbond peer", "MetalbondPeer", server)
				break
			}
		}
		if connected {
			break
		}
		if time.Now().After(deadline) {
			panic(errors.New("metalbond timeout waiting to connect"))
		}
		time.Sleep(1 * time.Second)
	}

	if enableIPv6Support {
		parsedIPv6SupportVersionStr, err := version.NewVersion(strings.TrimPrefix(dpserviceIPv6SupportVersionStr, "v"))
		if err != nil {
			fmt.Printf("error parsing defined dpservice version: %s\n", err)
			return
		}
		// Remove 'v' prefix and split at '-' to ignore build metadata if present
		verParts := strings.Split(strings.TrimPrefix(protoVersion.Spec.ServiceVersion, "v"), "-")
		ver, err := version.NewVersion(verParts[0])
		if err != nil {
			setupLog.Error(err, "unable to parse received version string", "Version", protoVersion.Spec.ServiceVersion)
			os.Exit(1)
		}
		if ver.LessThan(parsedIPv6SupportVersionStr) {
			setupLog.Error(err, "dpservice doesnt support IPv6 and metalnet ipv6 support is enabled", "Version", protoVersion.Spec.ServiceVersion)
			os.Exit(1)
		}
	}

	if err := metalnetclient.SetupNetworkInterfaceNetworkRefNameFieldIndexer(context.TODO(), mgr.GetFieldIndexer()); err != nil {
		setupLog.Error(err, "unable to set up field indexer", "Field", metalnetclient.NetworkInterfaceNetworkRefNameField)
		os.Exit(1)
	}

	if err := metalnetclient.SetupLoadBalancerNetworkRefNameFieldIndexer(context.TODO(), mgr.GetFieldIndexer()); err != nil {
		setupLog.Error(err, "unable to set up field indexer", "Field", metalnetclient.LoadBalancerNetworkRefNameField)
		os.Exit(1)
	}

	err = metalbondRouteUtil.Subscribe(ctx, metalbond.VNI(publicVNI))
	if err != nil {
		setupLog.Error(err, "unable to subscribe to metalbond's public VNI")
	}

	// wait using backoff for default router address to be set by subscription
	for i := 1; i <= 3; i++ {
		if defaultRouterAddr.SetBySubsciption {
			break
		}
		time.Sleep(time.Duration(100*i) * time.Millisecond)
	}

	defaultRouterAddr.RWMutex.Lock()
	if defaultRouterAddr.SetBySubsciption {
		if defaultRouterAddr.RouterAddress.Compare(netip.MustParseAddr(routerAddress.String())) != 0 {
			setupLog.Info("--router-address flag's value does not match the default router address set by subscription, using the latter")
		}
	} else if routerAddress.Equal(net.IP{}) {
		setupLog.Error(fmt.Errorf("must specify --router-address or obtain default router address via metalbond subscription"), "invalid values")
		os.Exit(1)
	} else {
		defaultRouterAddr.RouterAddress = netip.MustParseAddr(routerAddress.String())
		setupLog.Info("Couldn't obtain default router address via metalbond subscription, using --router-address flag's value")
	}
	defaultRouterAddr.RWMutex.Unlock()

	if strings.Contains(nodeName, bluefieldSuffix) {
		bluefieldDetected = true
		// In case string "-bluefield" in the node name, remove it
		nodeName = strings.Replace(nodeName, bluefieldSuffix, "", 1)
	}

	if err = (&controllers.NetworkReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		DPDK:              dpdkClient,
		RouteUtil:         metalbondRouteUtil,
		MetalnetCache:     metalnetCache,
		MetalnetMBClient:  metalnetMBClient,
		DefaultRouterAddr: &defaultRouterAddr,
		NodeName:          nodeName,
		EnableIPv6Support: enableIPv6Support,
		Control:           c,
	}).SetupWithManager(mgr, mgr.GetCache()); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Network")
		os.Exit(1)
	}
	if err = (&controllers.NetworkInterfaceReconciler{
		Client:                      mgr.GetClient(),
		EventRecorder:               mgr.GetEventRecorderFor("networkinterface"),
		Scheme:                      mgr.GetScheme(),
		DPDK:                        dpdkclient.NewClient(dpdkProtoClient),
		RouteUtil:                   metalbondRouteUtil,
		NetFnsManager:               netFnsManager,
		PfToVfOffset:                pfToVfOffset,
		SysFS:                       sysFS,
		NodeName:                    nodeName,
		PublicVNI:                   publicVNI,
		EnableIPv6Support:           enableIPv6Support,
		BluefieldDetected:           bluefieldDetected,
		BluefieldHostDefaultBusAddr: bluefieldHostDefaultBusAddr,
		MultiportEswitchMode:        multiportEswitchMode,
		Control:                     c,
	}).SetupWithManager(mgr, mgr.GetCache()); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NetworkInterface")
		os.Exit(1)
	}

	if err = (&controllers.LoadBalancerReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		EventRecorder:     mgr.GetEventRecorderFor("loadbalancer"),
		DPDK:              dpdkclient.NewClient(dpdkProtoClient),
		RouteUtil:         metalbondRouteUtil,
		MetalnetCache:     metalnetCache,
		NodeName:          nodeName,
		PublicVNI:         publicVNI,
		EnableIPv6Support: enableIPv6Support,
		Control:           c,
	}).SetupWithManager(mgr, mgr.GetCache()); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "LoadBalancer")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	var dpChecker healthz.Checker = func(_ *http.Request) error {
		uuid, err := dpdkProtoClient.CheckInitialized(context.Background(), &dpdkproto.CheckInitializedRequest{})
		if err != nil {
			return fmt.Errorf("dp-service down: %w", err)
		}
		if expectedUUID, actualUUID := dpdkUUID.GetUuid(), uuid.GetUuid(); expectedUUID != actualUUID {
			return fmt.Errorf("dp-service restart detected - %s | %s", expectedUUID, actualUUID)
		}
		return nil
	}
	if err := mgr.AddHealthzCheck("healthz", dpChecker); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("metalbond-peers-health", metalbondPeersHealthCheck(
		mbInstance,
		metalbondPeers,
		metalbondTxChanCapacity,
		metalbondRxChanEventCapacity,
		metalbondRxChanDataUpdateCapacity,
	)); err != nil {
		setupLog.Error(err, "unable to set up metalbond peers health check")
		os.Exit(1)
	}

	// Start the background worker for peer removal
	startPeerRemovalWorker(mbInstance)

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// metalbondPeersHealthCheck checks all peers for stale keepalives,
// flags unhealthy peers as pendingRemovals, and recreates peers that are fully removed.
func metalbondPeersHealthCheck(
	mbInstance *mb.MetalBond,
	metalbondPeers []string,
	txChanCapacity, rxChanEventCapacity, rxChanDataUpdateCapacity int,
) func(req *http.Request) error {
	return func(_ *http.Request) error {
		var unhealthyPeers []string

		for _, peer := range metalbondPeers {
			// 1) If peer is already pending removal, check if it's fully removed -> recreate
			if _, pending := pendingRemovals.Load(peer); pending {
				_, err := mbInstance.PeerState(peer)
				if err != nil && strings.Contains(err.Error(), "does not exist") {
					// The peer is confirmed gone; let's recreate
					pendingRemovals.Delete(peer)

					if err := mbInstance.AddPeer(peer, "", txChanCapacity, rxChanEventCapacity, rxChanDataUpdateCapacity); err != nil {
						log.Printf("failed to recreate peer %s: %v", peer, err)
						// If AddPeer fails, we do *not* remove it from metalbondPeers,
						// but you could store it back in pendingRemovals if you want to retry next pass:
						pendingRemovals.Store(peer, struct{}{})
						continue
					}
					log.Printf("Successfully recreated peer %s", peer)
				}
				// If PeerState() doesn’t error or is not “does not exist”,
				// we assume the removal is still in progress or the peer is in an intermediate state.
				continue
			}

			// 2) If not pending removal, check keepalive status
			lastKeepaliveSent, err := mbInstance.PeerLastKeepaliveSent(peer)
			if err != nil {
				// If the code returns “Peer does not exist,” store in pendingRemovals
				if strings.Contains(err.Error(), "does not exist") {
					pendingRemovals.Store(peer, struct{}{})
				} else {
					log.Printf("error retrieving last keepalive sent for peer %s: %v", peer, err)
				}
				continue
			}

			lastKeepaliveReceived, err := mbInstance.PeerLastKeepaliveReceived(peer)
			if err != nil {
				if strings.Contains(err.Error(), "does not exist") {
					pendingRemovals.Store(peer, struct{}{})
				} else {
					log.Printf("error retrieving last keepalive received for peer %s: %v", peer, err)
				}
				continue
			}

			// 3) If keepalives are stale, mark peer as unhealthy & schedule removal
			if time.Since(lastKeepaliveSent) > 1*time.Minute || time.Since(lastKeepaliveReceived) > 1*time.Minute {
				unhealthyPeers = append(unhealthyPeers, peer)
				pendingRemovals.Store(peer, struct{}{})
			}
		}

		// 4) Log any newly unhealthy peers for visibility
		if len(unhealthyPeers) > 0 {
			log.Printf("Detected unhealthy peers: %v. Pending removal.", unhealthyPeers)
		}

		// Return nil to indicate "healthy" from the controller-runtime perspective
		// (unless you want to degrade health if too many peers are in pendingRemovals)
		return nil
	}
}

// startPeerRemovalWorker runs in the background, periodically removing peers that are in pendingRemovals.
func startPeerRemovalWorker(mbInstance *mb.MetalBond) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			pendingRemovals.Range(func(key, _ interface{}) bool {
				peer, ok := key.(string)
				if !ok {
					return true
				}

				// Attempt to remove the peer.
				// If RemovePeer blocks for 30s, it just means we wait inside this iteration;
				// the rest of the loop won't be blocked because we do `return true` afterward.
				if err := mbInstance.RemovePeer(peer); err != nil {
					log.Printf("failed to remove peer %s: %v", peer, err)
					// Keep it in pendingRemovals so we can retry later
					return true
				}

				log.Printf("Successfully removed peer %s, awaiting recreation", peer)

				return true
			})
		}
	}()
}
