// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/jetstack/paranoia/pkg/output"
	"github.com/nlepage/go-tarfs"
	"github.com/spf13/cobra"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type FoundCert struct {
	Location    string
	Certificate *x509.Certificate
}

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

		defer func(name string) {
			err := os.Remove(name)
			if err != nil {
				panic(err)
			}
		}(tmpfile.Name())

		if OutputMode == output.ModePretty {
			fmt.Printf("Downloading container image %s\n", imageName)
		}
		img, err := crane.Pull(imageName)
		if err != nil {
			panic(err)
		}

		if OutputMode == output.ModePretty {
			fmt.Println("Exporting combined filesystem image")
		}
		err = crane.Export(img, tmpfile)
		if err != nil {
			panic(err)
		}
		err = tmpfile.Close()
		if err != nil {
			panic(err)
		}

		if OutputMode == output.ModePretty {
			fmt.Println("Inspecting container filesystem")
		}
		f, err := os.Open(tmpfile.Name())
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				panic(err)
			}
		}(f)

		tfs, err := tarfs.New(f)
		if err != nil {
			panic(err)
		}

		var foundCerts []FoundCert

		err = fs.WalkDir(tfs, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				panic(err)
			}
			if filepath.Ext(path) == ".crt" {
				data, err := fs.ReadFile(tfs, path)
				if err != nil {
					panic(err)
				}

				var block *pem.Block
				finished := false
				for !finished {
					block, data = pem.Decode(data)
					if block == nil {
						finished = true
					} else {
						if block.Type == "CERTIFICATE" {
							cert, err := x509.ParseCertificate(block.Bytes)
							if err != nil {
								panic(err)
							}
							foundCerts = append(foundCerts, FoundCert{
								Location:    path,
								Certificate: cert,
							})
						}
					}
				}
			}
			return nil
		})
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
