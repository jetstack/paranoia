// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/nlepage/go-tarfs"
	"github.com/spf13/cobra"
	"io/fs"
	"io/ioutil"
	"log"
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
			log.Fatal(err)
		}

		defer func(name string) {
			err := os.Remove(name)
			if err != nil {
				log.Fatal(err)
			}
		}(tmpfile.Name())

		log.Printf("Downloading container image %s\n", imageName)
		img, err := crane.Pull(imageName)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Exporting combined filesystem image")
		err = crane.Export(img, tmpfile)
		if err != nil {
			log.Fatal(err)
		}
		err = tmpfile.Close()
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Inspecting container filesystem")
		f, err := os.Open(tmpfile.Name())
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				log.Fatal(err)
			}
		}(f)

		tfs, err := tarfs.New(f)
		if err != nil {
			log.Fatal(err)
		}

		var foundCerts []FoundCert

		err = fs.WalkDir(tfs, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Fatal(err)
			}
			if filepath.Ext(path) == ".crt" {
				log.Printf("Found suspected certificates file %s\n", path)
				data, err := fs.ReadFile(tfs, path)
				if err != nil {
					log.Fatal(err)
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
								log.Fatal(err)
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
			log.Fatal(err)
		}

		log.Printf("Found %d certificates\n", len(foundCerts))
		for _, fc := range foundCerts {
			log.Printf("Found in %s: %s\n", fc.Location, fc.Certificate.Subject)
		}

		log.Println("Done")
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
