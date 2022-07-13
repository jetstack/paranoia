// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/image"
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"time"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all certificate data for later use",
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
			headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
			columnFmt := color.New(color.FgYellow).SprintfFunc()

			tbl := table.New("File Location", "Owner", "Not Before", "Not After", "SHA-256")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for _, fc := range foundCerts {
				tbl.AddRow(fc.Location,
					fc.Certificate.Issuer.CommonName,
					fc.Certificate.NotBefore.Format(time.RFC3339),
					fc.Certificate.NotAfter.Format(time.RFC3339),
					hex.EncodeToString(fc.FingerprintSha256[:]))
			}
			tbl.Print()
			fmt.Printf("Found %d certificates\n", len(foundCerts))
		} else if OutputMode == output.ModeJSON {
			o := output.JSONOutput{}
			o.Certificates = make([]output.JSONCertificate, len(foundCerts))
			for i, c := range foundCerts {
				o.Certificates[i] = output.JSONCertificate{
					FileLocation:      c.Location,
					Owner:             c.Certificate.Issuer.CommonName,
					Signature:         fmt.Sprintf("%X", c.Certificate.Signature),
					NotBefore:         c.Certificate.NotBefore.Format(time.RFC3339),
					NotAfter:          c.Certificate.NotAfter.Format(time.RFC3339),
					FingerprintSHA1:   hex.EncodeToString(c.FingerprintSha1[:]),
					FingerprintSHA256: hex.EncodeToString(c.FingerprintSha256[:]),
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
	rootCmd.AddCommand(exportCmd)
}
