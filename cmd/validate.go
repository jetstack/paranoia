// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/image"
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/jetstack/paranoia/pkg/validate"
)

var validateConfigurationFile string
var warn bool
var permissive bool

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate that the certificates in a container image conform to a provided config",
	Long: `Validate checks the trust bundles found in a given container image against policy
specified in a given configuration file (.paranoia.yaml by default). For example:

paranoia validate alpine:latest --config some-config.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		err := output.ValidateOutputMode(OutputMode)
		if err != nil {
			panic(err)
		}

		validateConfig, err := validate.LoadConfig(validateConfigurationFile)
		if err != nil {
			panic(err)
		}

		validator, err := validate.NewValidator(*validateConfig, permissive)
		fmt.Println("Validating certificates with " + validator.DescribeConfig())

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
			panic(err)
		}

		// We've written to the tmp file, and intend to read from it again, so seek back to the start
		_, err = tmpfile.Seek(0, 0)
		if err != nil {
			panic(err)
		}

		foundCerts, err := certificate.FindCertificates(tmpfile)
		if err != nil {
			panic(err)
		}

		r, err := validator.Validate(foundCerts)
		if err != nil {
			panic(err)
		}

		if r.IsPass() {
			fmt.Printf("Scanned %d certificates in image %s, no issues found.\n", len(foundCerts), imageName)
		} else {
			fmt.Printf("Scanned %d certificates in image %s, found issues.\n", len(foundCerts), imageName)
			for _, na := range r.NotAllowedCertificates {
				fmt.Printf("Certificate with SHA256 fingerprint %X in location %s was not allowed\n", na.FingerprintSha256, na.Location)
			}
			for _, f := range r.ForbiddenCertificates {
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
			println("Failed!")
			if !warn {
				os.Exit(1)
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringVarP(&validateConfigurationFile, "config", "c", ".paranoia.yaml", "Configuration file for Paranoia")
	validateCmd.PersistentFlags().BoolVar(&warn, "warn", false, "Suppress nonzero exit code on validation failures.")
	validateCmd.PersistentFlags().BoolVar(&permissive, "permissive", false, "Allow any certificate that is not otherwise forbidden. This overrides the config's allow list.")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// validateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// validateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
