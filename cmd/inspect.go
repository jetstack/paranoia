// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/analyse"
	"github.com/jetstack/paranoia/internal/image"
)

func newInspect(ctx context.Context) *cobra.Command {
	var imgOpts *options.Image
	var analyseOpts *options.Analyse

	cmd := &cobra.Command{
		Use:   "inspect [flags] image",
		Short: "Summarise potential issues with certificates",
		Long: `
Inspect prints out certificates that have one or more of the following faults:

- Expired (based on current system time).
- Close to expiry (based on current system time).
- Removed by Mozilla from their certificate authority bundle.

Partial certificates are also all printed for further inspection.
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			return options.MustSingleImageArgs(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]

			iOpts, err := imgOpts.Options()
			if err != nil {
				return errors.Wrap(err, "constructing image options")
			}

			parsedCertificates, err := image.FindImageCertificates(ctx, imageName, iOpts...)
			if err != nil {
				return err
			}

			analyser, err := analyse.NewAnalyser(analyseOpts.MozillaRemovedCertsURL)
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
					fingerprint := hex.EncodeToString(cert.FingerprintSha256[:])
					fmt.Printf("Certificate %s, Fingerprint: %s\n", cert.Certificate.Subject, fingerprint)
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
					fmt.Print(fmtFn("⚠️ Partial certificate found in file %s: %s\n", p.Location, p.Reason))
				}
				fmt.Printf("Found %d partial certificates\n", len(parsedCertificates.Partials))
			}

			return nil
		},
	}

	imgOpts = options.RegisterImage(cmd)
	analyseOpts = options.RegisterAnalyse(cmd)
	cmd.Args = cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs)

	return cmd
}
