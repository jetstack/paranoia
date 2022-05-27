// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/x509"
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

		fmt.Printf("Downloading container image %s\n", imageName)
		img, err := crane.Pull(imageName)
		if err != nil {
			panic(err)
		}

		fmt.Println("Exporting combined filesystem image")
		err = crane.Export(img, tmpfile)
		if err != nil {
			panic(err)
		}
		err = tmpfile.Close()
		if err != nil {
			panic(err)
		}

		fmt.Println("Inspecting container filesystem")
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
				fmt.Printf("Found suspected certificates file %s\n", path)
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

		fmt.Printf("Found %d certificates\n", len(foundCerts))
		for _, fc := range foundCerts {
			fmt.Printf("Found in %s: %s\n", fc.Location, fc.Certificate.Subject)
		}

		fmt.Println("Done")
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
