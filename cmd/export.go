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

	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/image"
	"github.com/jetstack/paranoia/internal/output"
)

func newExport(ctx context.Context) *cobra.Command {
	var outOpts *options.Output

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all certificate data for later use",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := options.MustSingleImageArgs(args); err != nil {
				return err
			}
			return outOpts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]

			foundCerts, partialCerts, err := image.FindImageCertificates(ctx, imageName)
			if err != nil {
				return err
			}

			if outOpts.Mode == options.OutputModePretty {
				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()

				tbl := table.New("File Location", "Parser", "Subject", "Not Before", "Not After", "SHA-256")
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

				for _, cert := range foundCerts {
					tbl.AddRow(cert.Location, cert.Parser, cert.Certificate.Subject,
						cert.Certificate.NotBefore.Format(time.RFC3339),
						cert.Certificate.NotAfter.Format(time.RFC3339),
						hex.EncodeToString(cert.FingerprintSha256[:]))
				}

				tbl.Print()
				fmt.Printf("Found %d certificates\n", len(foundCerts))

				if len(partialCerts) > 0 {
					headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
					columnFmt := color.New(color.FgYellow).SprintfFunc()

					tbl := table.New("File Location", "Parser", "Reason")
					tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

					for _, p := range partialCerts {
						tbl.AddRow(p.Location, p.Parser, p.Reason)
					}

					tbl.Print()
					fmt.Printf("Found %d partial certificates\n", len(partialCerts))
				}

			} else if outOpts.Mode == options.OutputModeJSON {
				var out output.JSONOutput

				for _, cert := range foundCerts {
					out.Certificates = append(out.Certificates, output.JSONCertificate{
						FileLocation:      cert.Location,
						Owner:             cert.Certificate.Subject.String(),
						Parser:            cert.Parser,
						Signature:         fmt.Sprintf("%X", cert.Certificate.Signature),
						NotBefore:         cert.Certificate.NotBefore.Format(time.RFC3339),
						NotAfter:          cert.Certificate.NotAfter.Format(time.RFC3339),
						FingerprintSHA1:   hex.EncodeToString(cert.FingerprintSha1[:]),
						FingerprintSHA256: hex.EncodeToString(cert.FingerprintSha256[:]),
					})
				}

				for _, p := range partialCerts {
					out.PartialCertificates = append(out.PartialCertificates, output.JSONPartialCertificate{
						FileLocation: p.Location,
						Parser:       p.Parser,
						Reason:       p.Reason,
					})
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

	outOpts = options.RegisterOutputs(cmd)

	return cmd
}
