// SPDX-License-Identifier: Apache-2.0

package options

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	OutputModePretty = "pretty"
	OutputModeJSON   = "json"
)

var outputModes = []string{OutputModePretty, OutputModeJSON}

// Output are options for configuring command outputs.
type Output struct {
	// Mode is the output format of the command. Defaults to "pretty".
	Mode string `json:"format"`
}

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

func RegisterOutputs(cmd *cobra.Command) *Output {
	var opts Output
	cmd.Flags().StringVarP(&opts.Mode, "output", "o", "pretty", "Output mode. Supported modes: "+strings.Join(outputModes, ", "))
	return &opts
}

func RegisterValidation(cmd *cobra.Command) *Validation {
	var opts Validation
	cmd.PersistentFlags().StringVarP(&opts.Config, "config", "c", ".paranoia.yaml", "Configuration file for Paranoia")
	cmd.PersistentFlags().BoolVar(&opts.Quiet, "quiet", false, "Suppress nonzero exit code on validation failures.")
	cmd.PersistentFlags().BoolVar(&opts.Permissive, "permissive", false, "Allow any certificate that is not otherwise forbidden. This overrides the config's allow list.")
	return &opts
}

func (o *Output) Validate() error {
	for _, m := range outputModes {
		if o.Mode == m {
			return nil
		}
	}
	return fmt.Errorf("invalid output mode %q, must be one of %s", o.Mode, strings.Join(outputModes, ", "))
}
