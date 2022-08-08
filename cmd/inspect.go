// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/jetstack/paranoia/pkg/analyse"
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect a container image for root certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := output.ValidateOutputMode(OutputMode)
		if err != nil {
			return err
		}

		imageName := args[0]

		foundCerts, err := findImageCertificates(context.TODO(), imageName)
		if err != nil {
			return err
		}

		analyser, err := analyse.NewAnalyser()
		if err != nil {
			return errors.Wrap(err, "failed to initialise analyser")
		}

		numIssues := 0
		for _, cert := range foundCerts {
			if cert.Certificate == nil {
				numIssues++
				continue
			}
			notes := analyser.AnalyseCertificate(cert.Certificate)
			if len(notes) > 0 {
				numIssues++
				fmt.Printf("Certificate %s\n", cert.Certificate.Subject)
				for i, n := range notes {
					var lead string
					if i == len(notes)-1 {
						lead = "┗"
					} else {
						lead = "┣"
					}
					var fmtFn func(format string, a ...interface{}) string
					var emoji string
					if n.Level == analyse.NoteLevelError {
						fmtFn = color.New(color.FgRed).SprintfFunc()
						emoji = "🚨"
					} else if n.Level == analyse.NoteLevelWarn {
						fmtFn = color.New(color.FgYellow).SprintfFunc()
						emoji = "⚠️"
					}
					fmt.Printf(lead + " " + fmtFn("%s %s\n", emoji, n.Reason))
				}
			}
		}
		fmt.Printf("Found %d certificates total, of which %d had issues\n", len(foundCerts), numIssues)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
