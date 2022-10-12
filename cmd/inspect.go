// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/analyse"
	"github.com/jetstack/paranoia/internal/image"
)

func newInspect(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a container image for root certificates",
		PreRunE: func(_ *cobra.Command, args []string) error {
			return options.MustSingleImageArgs(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]

			parsedCertificates, err := image.FindImageCertificates(ctx, imageName)
			if err != nil {
				return err
			}

			analyser, err := analyse.NewAnalyser()
			if err != nil {
				return errors.Wrap(err, "failed to initialise analyser")
			}

			numIssues := 0
			for _, cert := range parsedCertificates.Found {
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
			fmt.Printf("Found %d certificates total, of which %d had issues\n", len(parsedCertificates.Found), numIssues)
			if len(parsedCertificates.Partials) > 0 {
				for _, p := range parsedCertificates.Partials {
					fmtFn := color.New(color.FgYellow).SprintfFunc()
					fmt.Printf(fmtFn("⚠️ Partial certificate found in file %s: %s\n", p.Location, p.Reason))
				}
				fmt.Printf("Found %d partial certificates\n", len(parsedCertificates.Partials))
			}

			return nil
		},
	}
	return cmd
}
