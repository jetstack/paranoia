package options

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cliflag "k8s.io/component-base/cli/flag"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options is a struct to hold options for the paranoia controller
type Options struct {
	MetricsServingAddress string
	DefaultTestAll        bool
	CacheTimeout          time.Duration
	LogLevel              string

	PprofBindAddress        string
	GracefulShutdownTimeout time.Duration
	CacheSyncPeriod         time.Duration

	KubeConfigFlags *genericclioptions.ConfigFlags

	Client client.Options
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))

	o.KubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.KubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

	usageFmt := "Usage:\n  %s\n"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), nfs, 0)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), nfs, 0)
	})

	fs := cmd.Flags()
	for _, f := range nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) addAppFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.MetricsServingAddress,
		"metrics-serving-address", "m", "0.0.0.0:8080",
		"Address to serve metrics on at the /metrics path.")

	fs.StringVarP(&o.PprofBindAddress,
		"pprof-serving-address", "", "",
		"Address to serve pprof on for profiling.")

	fs.DurationVarP(&o.CacheTimeout,
		"image-cache-timeout", "c", time.Minute*30,
		"The time for an image version in the cache to be considered fresh. Images "+
			"will be rechecked after this interval.")

	fs.StringVarP(&o.LogLevel,
		"log-level", "v", "info",
		"Log level (debug, info, warn, error, fatal, panic).")

	fs.DurationVarP(&o.GracefulShutdownTimeout,
		"graceful-shutdown-timeout", "", 10*time.Second,
		"Time that the manager should wait for all controller to shutdown.")

	fs.DurationVarP(&o.CacheSyncPeriod,
		"cache-sync-period", "", 5*time.Hour,
		"The time in which all resources should be updated.")
}
