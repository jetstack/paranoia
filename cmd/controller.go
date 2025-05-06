package cmd

import (
	"context"
	"fmt"
	"net/http"

	logrusr "github.com/bombsimon/logrusr/v4"
	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/controller"
	"github.com/jetstack/paranoia/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func runController(ctx context.Context) *cobra.Command {
	opts := new(options.Options)

	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Run Paranoia as a Kubernetes Controller",
		Long:  "Run Paranoia as a Kubernetes Controller using controller-runtime.",
		RunE: func(_ *cobra.Command, _ []string) error {

			// Register custom metrics with Prometheus
			http.Handle("/metrics", promhttp.Handler())
			go func() {
				if err := http.ListenAndServe(opts.MetricsServingAddress, nil); err != nil {
					fmt.Printf("Failed to start metrics server: %s\n", err)
				}
			}()

			// Set up a new manager
			_, err := rest.InClusterConfig()
			if err != nil {
				return fmt.Errorf("unable to get cluster configuration: %w", err)
			}

			restConfig, err := opts.KubeConfigFlags.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("failed to build kubernetes rest config: %s", err)
			}

			logLevel, err := logrus.ParseLevel(opts.LogLevel)
			if err != nil {
				return fmt.Errorf("failed to parse --log-level %q: %s",
					opts.LogLevel, err)
			}

			log := newLogger(logLevel).WithField("component", "controller")
			ctrl.SetLogger(logrusr.New(log.WithField("controller", "manager").Logger))

			mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
				LeaderElection: false,
				Metrics: server.Options{
					BindAddress:   "0", // Disable default metrics server
					SecureServing: false,
				},
				GracefulShutdownTimeout: &opts.GracefulShutdownTimeout,
				Cache:                   cache.Options{SyncPeriod: &opts.CacheSyncPeriod},
				PprofBindAddress:        opts.PprofBindAddress,
			})
			if err != nil {
				return err
			}

			metricsServer := metrics.New(log, ctrmetrics.Registry, mgr.GetCache())

			c := controller.NewPodReconciler(
				mgr.GetClient(),
				log,
				metricsServer,
			)

			if err := c.SetupWithManager(mgr); err != nil {
				return fmt.Errorf("failed to setup controller: %s", err)
			}
			log.Info("starting manager")
			if err := mgr.Start(ctx); err != nil {
				return fmt.Errorf("failed to start manager: %s", err)
			}
			return nil
		},
	}
	opts.AddFlags(cmd)
	return cmd
}
