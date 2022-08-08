// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"

	"github.com/jetstack/paranoia/pkg/output"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all certificate data for later use",
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

		if OutputMode == output.ModePretty {
			headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
			columnFmt := color.New(color.FgYellow).SprintfFunc()

			tbl := table.New("File Location", "Parser", "Reason", "Not Before", "Not After", "SHA-256")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for _, cert := range foundCerts {
				if cert.Certificate == nil {
					tbl.AddRow(cert.Location, cert.Parser, cert.Reason, "-", "-", "-")
				} else {
					tbl.AddRow(cert.Location, cert.Parser, cert.Reason,
						cert.Certificate.NotBefore.Format(time.RFC3339),
						cert.Certificate.NotAfter.Format(time.RFC3339),
						hex.EncodeToString(cert.FingerprintSha256[:]))
				}
			}

			tbl.Print()
			fmt.Printf("Found %d certificates\n", len(foundCerts))

		} else if OutputMode == output.ModeJSON {
			var out output.JSONOutput

			for _, cert := range foundCerts {
				if cert.Certificate == nil {
					out.Certificates = append(out.Certificates, output.JSONCertificate{
						FileLocation: cert.Location,
						Owner:        cert.Reason,
					})
				} else {
					out.Certificates = append(out.Certificates, output.JSONCertificate{
						FileLocation:      cert.Location,
						Owner:             cert.Reason,
						Signature:         fmt.Sprintf("%X", cert.Certificate.Signature),
						NotBefore:         cert.Certificate.NotBefore.Format(time.RFC3339),
						NotAfter:          cert.Certificate.NotAfter.Format(time.RFC3339),
						FingerprintSHA1:   hex.EncodeToString(cert.FingerprintSha1[:]),
						FingerprintSHA256: hex.EncodeToString(cert.FingerprintSha256[:]),
					})
				}
			}

			m, err := json.Marshal(out)
			if err != nil {
				return errors.Wrap(err, "failed to marshall output JSON")
			}

			fmt.Println(string(m))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
}
