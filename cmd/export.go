// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
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
	var (
		imgOpts *options.Image
		outOpts *options.Output
	)

	cmd := &cobra.Command{
		Use:   "export [flags] image",
		Short: "Export all certificate authorities in the given container image",
		Long: `
Exports all certificates found in the container image.
The detail available depends on the output mode used

In most output modes, partial certificates are also included after the main output.
`,
		Example: `
Export certificates for an image:

	$ paranoia export alpine:latest

Pipe certificate information into jq:

	$ paranoia export --output json alpine:latest | jq '.certificates[].fingerprintSHA256'
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := options.MustSingleImageArgs(args); err != nil {
				return err
			}
			return outOpts.Validate()
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

			if outOpts.Mode == options.OutputModePretty || outOpts.Mode == options.OutputModeWide {
				wide := outOpts.Mode == options.OutputModeWide
				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()

				var tbl table.Table
				if wide {
					tbl = table.New("File Location", "Parser", "Subject", "Not Before", "Not After", "SHA-256")
				} else {
					tbl = table.New("File Location", "Subject")
				}
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

				for _, cert := range parsedCertificates.Found {
					if wide {
						tbl.AddRow(cert.Location, cert.Parser, cert.Certificate.Subject,
							cert.Certificate.NotBefore.Format(time.RFC3339),
							cert.Certificate.NotAfter.Format(time.RFC3339),
							hex.EncodeToString(cert.FingerprintSha256[:]))
					} else {
						tbl.AddRow(cert.Location, cert.Certificate.Subject)
					}
				}

				tbl.Print()
				fmt.Printf("Found %d certificates\n", len(parsedCertificates.Found))

				if len(parsedCertificates.Partials) > 0 {
					headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
					columnFmt := color.New(color.FgYellow).SprintfFunc()

					tbl := table.New("File Location", "Parser", "Reason")
					tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

					for _, p := range parsedCertificates.Partials {
						tbl.AddRow(p.Location, p.Parser, p.Reason)
					}

					tbl.Print()
					fmt.Printf("Found %d partial certificates\n", len(parsedCertificates.Partials))
				}

			} else if outOpts.Mode == options.OutputModeJSON {
				var out output.JSONOutput

				for _, cert := range parsedCertificates.Found {
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

				for _, p := range parsedCertificates.Partials {
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
			} else if outOpts.Mode == options.OutputModePEM {
				for _, cert := range parsedCertificates.Found {
					pem.Encode(os.Stdout, &pem.Block{
						Type:  "CERTIFICATE",
						Bytes: cert.Certificate.Raw,
					})
				}
			}

			return nil
		},
	}

	imgOpts = options.RegisterImage(cmd)
	outOpts = options.RegisterOutputs(cmd)
	cmd.Args = cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs)

	return cmd
}
