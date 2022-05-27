// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/nlepage/go-tarfs"
	"io/fs"
	"os"
	"path/filepath"
)

type FoundCertificate struct {
	Location    string
	Certificate *x509.Certificate
}

// FindCertificates will scan a container image, given as a file handler to a TAR file, for certificates and return them.
func FindCertificates(imageTar *os.File) ([]FoundCertificate, error) {
	tfs, err := tarfs.New(imageTar)
	if err != nil {
		return nil, err
	}

	var foundCerts []FoundCertificate

	err = fs.WalkDir(tfs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".crt" {
			data, err := fs.ReadFile(tfs, path)
			if err != nil {
				return err
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
							return err
						}
						foundCerts = append(foundCerts, FoundCertificate{
							Location:    path,
							Certificate: cert,
						})
					}
				}
			}
		}
		return nil
	})
	return foundCerts, err
}
