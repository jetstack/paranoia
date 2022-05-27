// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/image"
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"time"
)

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect a container image for root certificates",
	Run: func(cmd *cobra.Command, args []string) {
		err := output.ValidateOutputMode(OutputMode)
		if err != nil {
			panic(err)
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

		if OutputMode == output.ModePretty {
			fmt.Printf("Found %d certificates\n", len(foundCerts))
			for _, fc := range foundCerts {
				fmt.Printf("Found in %s: %s\n", fc.Location, fc.Certificate.Subject)
			}
			fmt.Println("Done")
		} else if OutputMode == output.ModeJSON {
			o := output.JSONOutput{}
			o.Certificates = make([]output.JSONCertificate, len(foundCerts))
			for i, c := range foundCerts {
				o.Certificates[i] = output.JSONCertificate{
					FileLocation: c.Location,
					Owner:        c.Certificate.Issuer.CommonName,
					Signature:    fmt.Sprintf("%X", c.Certificate.Signature),
					NotBefore:    c.Certificate.NotBefore.Format(time.RFC3339),
					NotAfter:     c.Certificate.NotAfter.Format(time.RFC3339),
				}
			}

			m, err := json.Marshal(o)
			if err != nil {
				panic(err)
			}

			fmt.Println(string(m))
		}

	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
