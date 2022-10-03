package options

import "github.com/spf13/cobra"

// Validation are options for configuring validation command.
type Validation struct {
	// Config is the filepath location to the validation configuration.
	Config string `json:"config"`

	// Quiet suppresses non-zero exit codes on validation failures.
	Quiet bool `json:"quiet"`

	// Permissive allows any certificate that is not otherwise forbidden. This
	// overrides the config's allow list.
	Permissive bool `json:"permissive"`
}

func RegisterValidation(cmd *cobra.Command) *Validation {
	var opts Validation
	cmd.PersistentFlags().StringVarP(&opts.Config, "config", "c", ".paranoia.yaml", "Configuration file for Paranoia")
	cmd.PersistentFlags().BoolVar(&opts.Quiet, "quiet", false, "Suppress nonzero exit code on validation failures.")
	cmd.PersistentFlags().BoolVar(&opts.Permissive, "permissive", false, "Allow any certificate that is not otherwise forbidden. This overrides the config's allow list.")
	return &opts
}
