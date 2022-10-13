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
	OutputModeWide   = "wide"
)

var outputModes = []string{OutputModePretty, OutputModeJSON, OutputModeWide}

// Output are options for configuring command outputs.
type Output struct {
	// Mode is the output format of the command. Defaults to "pretty".
	Mode string `json:"format"`
}

func RegisterOutputs(cmd *cobra.Command) *Output {
	var opts Output
	cmd.Flags().StringVarP(&opts.Mode, "output", "o", "pretty", "Output mode. Supported modes: "+strings.Join(outputModes, ", "))
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
