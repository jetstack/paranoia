// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "paranoia",
	Short: "Inspect container image trust bundles",
	Long:  `Paranoia is a CLI tool to inspect the trust bundles present in a container image.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "pretty", "Output mode. Supported modes: "+strings.Join(output.Modes, ", "))
}
