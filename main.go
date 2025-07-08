// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	goflag "flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
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
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(networkingv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var secureMetrics bool
	var metricsCertPath, metricsCertName, metricsCertKey string
	var enableHTTP2 bool
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
	var tlsOpts []func(*tls.Config)
	var metalbondTxChanCapacity int
	var metalbondRxChanEventCapacity int
	var metalbondRxChanDataUpdateCapacity int

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
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
	flag.BoolVar(&multiportEswitchMode, "multiport-eswitch", false, "Enable multiport eswitch support (can be overridden in metalnet-dir)")
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
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(goflag.CommandLine)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	if metalbondDebug {
		log.SetLevel(log.DebugLevel)
	}

	// detect multiport-eswitch mode automatically (overrides command-line)
	// Usage example: 'echo "eswitch" > /var/lib/metalnet/mode'
	modeFilePath := filepath.Join(metalnetDir, "mode")
	content, err := os.ReadFile(modeFilePath)
	if err == nil {
		multiportEswitchMode = strings.TrimSpace(string(content)) == "eswitch"
	}
	setupLog.Info(fmt.Sprintf("Multiport Eswitch mode set to: %v", multiportEswitchMode))

	defaultRouterAddr.PublicVNI = uint32(publicVNI)
	defaultRouterAddr.SetBySubsciption = false

	sysFS, err := sysfs.NewDefaultFS()
	if err != nil {
		setupLog.Error(err, "error creating sysfs")
		os.Exit(1)
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/controller/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.

	// Create watchers for metrics certificates
	var metricsCertWatcher *certwatcher.CertWatcher

	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(metricsCertPath, metricsCertName),
			filepath.Join(metricsCertPath, metricsCertKey),
		)
		if err != nil {
			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       fmt.Sprintf("%s.metalnet.ironcore.dev", nodeName),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if metricsCertWatcher != nil {
		setupLog.Info("Adding metrics certificate watcher to manager")
		if err := mgr.Add(metricsCertWatcher); err != nil {
			setupLog.Error(err, "unable to add metrics certificate watcher to manager")
			os.Exit(1)
		}
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
		initAvailable, err = netfns.CollectTAPFunctions([]string{"dtapvf_0", "dtapvf_1", "dtapvf_2", "dtapvf_3"})
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

	dpdkProtoClient := dpdkproto.NewDPDKironcoreClient(conn)
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

	for _, metalbondPeer := range metalbondPeers {
		if err := mbInstance.AddPeer(metalbondPeer, "", metalbondTxChanCapacity, metalbondRxChanEventCapacity, metalbondRxChanDataUpdateCapacity); err != nil {
			setupLog.Error(err, "failed to add metalbond peer", "MetalbondPeer", metalbondPeer)
			os.Exit(1)
		}
	}

	metalnetMBClient.SetMetalBond(mbInstance)

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
		os.Exit(1)
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
		TapDeviceMode:               tapDeviceMod,
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
