package options

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jetstack/paranoia/internal/client"
	"github.com/jetstack/paranoia/internal/client/selfhosted"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cliflag "k8s.io/component-base/cli/flag"
)

const (
	envPrefix = "PARANOIA"

	envGCRAccessToken = "GCR_TOKEN"

	envSelfhostedPrefix    = "SELFHOSTED"
	envSelfhostedUsername  = "USERNAME"
	envSelfhostedPassword  = "PASSWORD"
	envSelfhostedHost      = "HOST"
	envSelfhostedBearer    = "TOKEN" // #nosec G101
	envSelfhostedTokenPath = "TOKEN_PATH"
	envSelfhostedInsecure  = "INSECURE"
	envSelfhostedCAPath    = "CA_PATH"
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
	selfhosted      selfhosted.Options

	Client client.Options
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))
	o.addAuthFlags(nfs.FlagSet("Auth"))

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

var (
	selfhostedHostReg     = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_HOST_(.*)")
	selfhostedUsernameReg = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_USERNAME_(.*)")
	selfhostedPasswordReg = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_PASSWORD_(.*)")
	selfhostedTokenPath   = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_TOKEN_PATH_(.*)")
	selfhostedTokenReg    = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_TOKEN_(.*)")
	selfhostedCAPath      = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_CA_PATH_(.*)")
	selfhostedInsecureReg = regexp.MustCompile("^VERSION_CHECKER_SELFHOSTED_INSECURE_(.*)")
)

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

func (o *Options) addAuthFlags(fs *pflag.FlagSet) {

	/// GCR
	fs.StringVar(&o.Client.GCR.Token,
		"gcr-token", "",
		fmt.Sprintf(
			"Access token for read access to private GCR registries (%s_%s).",
			envPrefix, envGCRAccessToken,
		))
	///
	/// Selfhosted
	fs.StringVar(&o.selfhosted.Username,
		"selfhosted-username", "",
		fmt.Sprintf(
			"Username is authenticate with a selfhosted registry (%s_%s_%s).",
			envPrefix, envSelfhostedPrefix, envSelfhostedUsername,
		))
	fs.StringVar(&o.selfhosted.Password,
		"selfhosted-password", "",
		fmt.Sprintf(
			"Password is authenticate with a selfhosted registry (%s_%s_%s).",
			envPrefix, envSelfhostedPrefix, envSelfhostedPassword,
		))
	fs.StringVar(&o.selfhosted.Bearer,
		"selfhosted-token", "",
		fmt.Sprintf(
			"Token to authenticate to a selfhosted registry. Cannot be used with "+
				"username/password (%s_%s_%s).",
			envPrefix, envSelfhostedPrefix, envSelfhostedBearer,
		))
	fs.StringVar(&o.selfhosted.TokenPath,
		"selfhosted-token-path", "",
		fmt.Sprintf(
			"Override the default selfhosted registry's token auth path. "+
				"(%s_%s_%s).",
			envPrefix, envSelfhostedPrefix, envSelfhostedTokenPath,
		))
	fs.StringVar(&o.selfhosted.Host,
		"selfhosted-registry-host", "",
		fmt.Sprintf(
			"Full host of the selfhosted registry. Include http[s] scheme (%s_%s_%s)",
			envPrefix, envSelfhostedPrefix, envSelfhostedHost,
		))
	fs.StringVar(&o.selfhosted.CAPath,
		"selfhosted-registry-ca-path", "",
		fmt.Sprintf(
			"Absolute path to a PEM encoded x509 certificate chain. (%s_%s_%s)",
			envPrefix, envSelfhostedPrefix, envSelfhostedCAPath,
		))
	fs.BoolVarP(&o.selfhosted.Insecure,
		"selfhosted-insecure", "", false,
		fmt.Sprintf(
			"Enable/Disable SSL Certificate Validation. WARNING: "+
				"THIS IS NOT RECOMMENDED AND IS INTENDED FOR DEBUGGING (%s_%s_%s)",
			envPrefix, envSelfhostedPrefix, envSelfhostedInsecure,
		))
	// if !validSelfHostedOpts(o) {
	// 	panic(fmt.Errorf("invalid self hosted configuration"))
	// }
}

func (o *Options) assignSelfhosted(envs []string) {
	if o.Client.Selfhosted == nil {
		o.Client.Selfhosted = make(map[string]*selfhosted.Options)
	}

	initOptions := func(name string) {
		if o.Client.Selfhosted[name] == nil {
			o.Client.Selfhosted[name] = new(selfhosted.Options)
		}
	}

	regexActions := map[*regexp.Regexp]func(matches []string, value string){
		selfhostedHostReg: func(matches []string, value string) {
			initOptions(matches[1])
			o.Client.Selfhosted[matches[1]].Host = value
		},
		selfhostedUsernameReg: func(matches []string, value string) {
			initOptions(matches[1])
			o.Client.Selfhosted[matches[1]].Username = value
		},
		selfhostedPasswordReg: func(matches []string, value string) {
			initOptions(matches[1])
			o.Client.Selfhosted[matches[1]].Password = value
		},
		selfhostedTokenPath: func(matches []string, value string) {
			initOptions(matches[1])
			o.Client.Selfhosted[matches[1]].TokenPath = value
		},
		selfhostedTokenReg: func(matches []string, value string) {
			initOptions(matches[1])
			o.Client.Selfhosted[matches[1]].Bearer = value
		},
		selfhostedInsecureReg: func(matches []string, value string) {
			initOptions(matches[1])
			if val, err := strconv.ParseBool(value); err == nil {
				o.Client.Selfhosted[matches[1]].Insecure = val
			}
		},
		selfhostedCAPath: func(matches []string, value string) {
			initOptions(matches[1])
			o.Client.Selfhosted[matches[1]].CAPath = value
		},
	}

	for _, env := range envs {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) != 2 || len(pair[1]) == 0 {
			continue
		}

		key := strings.ToUpper(pair[0])
		value := pair[1]

		for regex, action := range regexActions {
			if matches := regex.FindStringSubmatch(key); len(matches) == 2 {
				action(matches, value)
				break
			}
		}
	}

	if len(o.selfhosted.Host) > 0 {
		o.Client.Selfhosted[o.selfhosted.Host] = &o.selfhosted
	}
	if !validSelfHostedOpts(o) {
		panic(fmt.Errorf("invalid self hosted configuration"))
	}
}

func (o *Options) Complete() {
	o.Client.Selfhosted = make(map[string]*selfhosted.Options)

	envs := os.Environ()
	for _, opt := range []struct {
		key    string
		assign *string
	}{
		{envGCRAccessToken, &o.Client.GCR.Token},
	} {
		for _, env := range envs {
			if o.assignEnv(env, opt.key, opt.assign) {
				break
			}
		}
	}

	o.assignSelfhosted(envs)
}

func validSelfHostedOpts(opts *Options) bool {
	// opts set using env vars
	if opts.Client.Selfhosted != nil {
		for _, selfHostedOpts := range opts.Client.Selfhosted {
			if !isValidOption(selfHostedOpts.Host, "") {
				return false
			}
		}
	}

	// opts set using flags
	if opts.selfhosted != (selfhosted.Options{}) {
		return isValidOption(opts.selfhosted.Host, "")
	}
	return true
}

func (o *Options) assignEnv(env, key string, assign *string) bool {
	pair := strings.SplitN(env, "=", 2)
	if len(pair) < 2 {
		return false
	}

	if envPrefix+"_"+key == pair[0] && len(*assign) == 0 {
		*assign = pair[1]
		return true
	}

	return false
}

func isValidOption(option, invalid string) bool {
	return option != invalid
}
