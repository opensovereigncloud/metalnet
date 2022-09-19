/*
Copyright 2022 The Metal Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	mb "github.com/onmetal/metalbond"
	dpdkproto "github.com/onmetal/net-dpservice-go/proto"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	networkingv1alpha1 "github.com/onmetal/metalnet/api/v1alpha1"
	"github.com/onmetal/metalnet/controllers"
	//+kubebuilder:scaffold:imports
)

var (
	scheme      = runtime.NewScheme()
	setupLog    = ctrl.Log.WithName("setup")
	hostName, _ = os.Hostname()
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
	var dpserviceAddr string
	var metalbondServerAddr string
	var metalbondServerPort string
	var publicVNI int
	var dpUUID string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&nodeName, "node-name", hostName, "The node name to react to when reconciling network interfaces.")
	flag.StringVar(&dpserviceAddr, "dpservice-address", "127.0.0.1:1337", "The address of net-dpservice.")
	flag.StringVar(&metalbondServerAddr, "metalbondserver-address", "", "The address of metal bond address server.")
	flag.StringVar(&metalbondServerPort, "metalbondserver-port", "4711", "The port of metal bond server.")
	flag.IntVar(&publicVNI, "public-vni", 100, "Virtual network identifier used for public routing announcements.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if metalbondServerAddr == "" {
		setupLog.Error(fmt.Errorf("must specify --metalbondserver-address"), "Invalid command line flags")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       fmt.Sprintf("%s.metalnet.onmetal.de", nodeName),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// setup net-dpservice client
	var dpdkClient dpdkproto.DPDKonmetalClient
	if dpserviceAddr != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		conn, err := grpc.DialContext(ctx, dpserviceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		defer func() {
			if err := conn.Close(); err != nil {
				setupLog.Error(err, "unable to close dpdk connection")
			}
		}()

		if err != nil {
			setupLog.Error(err, "unable create dpdk client")
			os.Exit(1)
		}
		dpdkClient = dpdkproto.NewDPDKonmetalClient(conn)
	}

	var metalbondClient mb.Client
	config := mb.Config{
		KeepaliveInterval: 3,
	}

	metalbondClient, err = controllers.NewMetalbondClient(controllers.MetalbondClientConfig{
		IPv4Only:          true,
		DPDKonmetalClient: dpdkClient,
	})
	if err != nil {
		setupLog.Error(err, "failed to initiliaze metalbond client")
		os.Exit(1)
	}
	mbInstance := mb.NewMetalBond(config, metalbondClient)

	// for now, only one metalbond server is used
	if err := mbInstance.AddPeer(fmt.Sprintf("[%s]:%s", metalbondServerAddr, metalbondServerPort)); err != nil {
		setupLog.Error(err, "failed to add/connect metalbond server")
		os.Exit(1)
	}

	nfDeviceBase, err := controllers.NewNFDeviceBase()
	if err != nil {
		setupLog.Error(err, "unable to start manager, Devicebase init failure")
		os.Exit(1)
	}

	initConf := dpdkproto.InitConfig{}
	_, err = dpdkClient.Init(context.Background(), &initConf)

	if err != nil {
		setupLog.Error(err, "dp-service can not be initialized")
		os.Exit(1)
	}

	em := dpdkproto.Empty{}
	uuid, err := dpdkClient.Initialized(context.Background(), &em)
	if err != nil {
		setupLog.Error(err, "dp-service down")
		os.Exit(1)
	}
	dpUUID = (*uuid).Uuid

	if err = (&controllers.NetworkReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Network")
		os.Exit(1)
	}
	if err = (&controllers.NetworkInterfaceReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		DPDKClient:      dpdkClient,
		NodeName:        nodeName,
		PublicVNI:       publicVNI,
		MbInstance:      mbInstance,
		RouterAddress:   metalbondServerAddr,
		DeviceAllocator: nfDeviceBase,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NetworkInterface")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	var dpChecker healthz.Checker = func(_ *http.Request) error {
		uuid, err := dpdkClient.Initialized(context.Background(), &em)
		if err != nil {
			return errors.New("dp-service down")
		}
		if dpUUID != (*uuid).Uuid {
			return errors.New("dp-service restart detected")
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
