// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/image"
	"github.com/jetstack/paranoia/internal/validate"
)

func newValidation(ctx context.Context) *cobra.Command {
	var (
		outOpts *options.Output
		valOpts *options.Validation
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate that the certificates in a container image conform to a provided config",
		Long: `Validate checks the trust bundles found in a given container image against policy
specified in a given configuration file (.paranoia.yaml by default). For example:

paranoia validate alpine:latest --config some-config.yaml`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := options.MustSingleImageArgs(args); err != nil {
				return err
			}
			return outOpts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			validateConfig, err := validate.LoadConfig(valOpts.Config)
			if err != nil {
				return errors.Wrap(err, "failed to load validator config")
			}

			validator, err := validate.NewValidator(*validateConfig, valOpts.Permissive)
			if err != nil {
				return errors.Wrap(err, "failed to initialise validator")
			}
			fmt.Println("Validating certificates with " + validator.DescribeConfig())

			imageName := args[0]

			foundCerts, err := image.FindImageCertificates(context.TODO(), imageName)
			if err != nil {
				return err
			}

			validateRes, err := validator.Validate(foundCerts)
			if err != nil {
				return err
			}

			if validateRes.IsPass() {
				fmt.Printf("Scanned %d certificates in image %s, no issues found.\n", len(foundCerts), imageName)
			} else {
				fmt.Printf("Scanned %d certificates in image %s, found issues.\n", len(foundCerts), imageName)
				for _, na := range validateRes.NotAllowedCertificates {
					fmt.Printf("Certificate with SHA256 fingerprint %X in location %s was not allowed\n", na.FingerprintSha256, na.Location)
				}
				for _, f := range validateRes.ForbiddenCertificates {
					sb := strings.Builder{}
					sb.WriteString("Certificate with ")
					if f.Entry.Fingerprints.Sha1 != "" {
						sb.WriteString(fmt.Sprintf("SHA1 %X", f.Certificate.FingerprintSha1))
					} else if f.Entry.Fingerprints.Sha256 != "" {
						sb.WriteString(fmt.Sprintf("SHA256 %X", f.Certificate.FingerprintSha256))
					}
					sb.WriteString(fmt.Sprintf(" in location %s was forbidden!", f.Certificate.Location))
					if f.Entry.Comment != "" {
						sb.WriteString(" Comment: ")
						sb.WriteString(f.Entry.Comment)
					} else {
						sb.WriteString(" No comment was provided.")
					}
					fmt.Println(sb.String())
				}
				for _, req := range validateRes.RequiredButAbsent {
					sb := strings.Builder{}
					sb.WriteString("Certificate with ")
					if req.Fingerprints.Sha1 != "" {
						sb.WriteString(fmt.Sprintf("SHA1 %s", req.Fingerprints.Sha1))
					} else if req.Fingerprints.Sha256 != "" {
						sb.WriteString(fmt.Sprintf("SHA256 %s", req.Fingerprints.Sha256))
					}
					sb.WriteString(" was required, but was not found")
					if req.Comment != "" {
						sb.WriteString(" Comment: ")
						sb.WriteString(req.Comment)
					} else {
						sb.WriteString(" No comment was provided.")
					}
					fmt.Println(sb.String())
				}
				if !valOpts.Quiet {
					os.Exit(1)
				}
			}

			return nil
		},
	}

	outOpts = options.RegisterOutputs(cmd)
	valOpts = options.RegisterValidation(cmd)

	return cmd
}
