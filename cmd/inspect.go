// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/jetstack/paranoia/pkg/analyse"
	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/image"
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
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

		tmpfile, err := ioutil.TempFile("", "paranoia")
		if err != nil {
			panic(err)
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				panic(err)
			}
			err = os.Remove(f.Name())
			if err != nil {
				panic(err)
			}
		}(tmpfile)

		err = image.PullAndExport(imageName, tmpfile)
		if err != nil {
			return errors.Wrap(err, "failed to download container image")
		}

		// We've written to the tmp file, and intend to read from it again, so seek back to the start
		_, err = tmpfile.Seek(0, 0)
		if err != nil {
			return errors.Wrap(err, "failed to seek to beginning of exported file")
		}

		foundCerts, err := certificate.FindCertificates(tmpfile)
		if err != nil {
			return errors.Wrap(err, "failed to search for certificates in container image")
		}

		analyser, err := analyse.NewAnalyser()
		if err != nil {
			return errors.Wrap(err, "failed to initialise analyser")
		}

		numIssues := 0
		for _, fc := range foundCerts {
			notes := analyser.AnalyseCertificate(fc.Certificate)
			if len(notes) > 0 {
				numIssues++
				fmt.Printf("Certificate %s\n", fc.Certificate.Subject)
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
