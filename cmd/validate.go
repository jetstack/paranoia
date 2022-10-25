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
		imgOpts *options.Image
		valOpts *options.Validation
	)

	cmd := &cobra.Command{
		Use:   "validate [flags] image",
		Short: "Validate that the certificates in a container image conform to a provided config",
		Long: `
Check certificates found in a given container image against policy in a configuration file.
If the policy is violated, then Paranoia will output issues to the command line and give a non-zero exit code.

## POLICY

Paranoia can do three different things with certificates in this mode.
Certificates are generally identified by either their SHA256 or SHA1 fingerprints.
SHA256 is preferred where possible.

### Require

If a certificate is required then Paranoia will fail if it is not present in the container.
As a reminder, this does not guarantee that the program will correctly trust this certificate, just that it is present.

### Allow

Allow a certificate, giving no error if it is found.
Required certificates are implicitly allowed, there is no need to duplicate the entry.

By default, Paranoia will error on any certificate not explicitly allowed (or required).
The *--permissive* flag will disable this behaviour, and allow any certificate not explicitly forbidden.

### Forbid

Forbid a certificate.
Paranoia will always error if it finds a forbidden certificate in a container image.

## CONFIGURATION FILE

The configuration file is a YAML formatted text file.
By default Paranoia uses a file named .paranoia.yaml in the working directory, but the *--config* flag can be used to override this.

This file should contain a "version" key at the root level.
Presently this should be set to the string "1".
Future versions of Paranoia may use different values for this key.

Next it may contain the "require", "allow", and "forbid" keys.
The behaviour of these keys is described above.
Each of these keys is a list of certificate entries.

Each certificate entry may contain the key "comment" with any commentary about the certificate.
It must contain a "fingerprints" key, with one of "sha1" or "sha256" containing the SHA1 or SHA256 fingerprint of the certificate respectively.
If both SHA1 and SHA256 fingerprints are given, the SHA1 is ignored.`,
		Example: `
An example configuration file: 

	version: "1"
	require:
	  - comment: "DigitCert Global Root"
	    fingerprints:
	      sha256: 4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161
	allow:
	  - comment: "ISRG X1 Root"
	    fingerprints:
	      sha256: 96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6
	forbid:
	  - comment: "An internal-only cert"
	    fingerprints:
	      sha256: bd40be0eccfce513ab318882f03962e4e2ec3799b51392e82805d9249e426d28

Validating a locally built image, using the implicit .paranoia.yaml configuration file:

	$ docker build . -t example.com/image:v0.1.0
	$ docker save example.com/image:v0.1.0 | paranoia validate -
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := options.MustSingleImageArgs(args); err != nil {
				return err
			}
			return nil
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

			iOpts, err := imgOpts.Options()
			if err != nil {
				return errors.Wrap(err, "constructing image options")
			}

			// Validate operates only on full certificates, and ignores partials.
			parsedCertificates, err := image.FindImageCertificates(context.TODO(), imageName, iOpts...)
			if err != nil {
				return err
			}

			validateRes, err := validator.Validate(parsedCertificates.Found)
			if err != nil {
				return err
			}

			if validateRes.IsPass() {
				fmt.Printf("Scanned %d certificates in image %s, no issues found.\n", len(parsedCertificates.Found), imageName)
			} else {
				fmt.Printf("Scanned %d certificates in image %s, found issues.\n", len(parsedCertificates.Found), imageName)
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

	imgOpts = options.RegisterImage(cmd)
	valOpts = options.RegisterValidation(cmd)
	cmd.Args = cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs)

	return cmd
}
