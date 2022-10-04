// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	crapi "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"

	"github.com/jetstack/paranoia/internal/certificate"
)

// FindImageCertificate will pull or load the image with the given name, scan
// for X.509 certificates, and return the result.
func FindImageCertificates(ctx context.Context, name string) ([]certificate.Found, error) {
	name = strings.TrimSpace(name)

	var (
		img crapi.Image
		err error
	)
	switch {
	case name == "-":
		var f *os.File
		f, err = os.CreateTemp(os.TempDir(), "paranoia-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary file: %w", err)
		}
		defer os.RemoveAll(f.Name())

		if _, err := io.Copy(f, os.Stdin); err != nil {
			return nil, fmt.Errorf("failed to write image to temporary file: %w", err)
		}

		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("failed to close temporary file: %w", err)
		}

		img, err = crane.Load(f.Name())
	case strings.HasPrefix(name, "file://"):
		img, err = crane.Load(strings.TrimPrefix(name, "file://"))
	default:
		img, err = crane.Pull(name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load image: %w", err)
	}

	var exportErr error
	exportDone := make(chan struct{})
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		if err := crane.Export(img, w); err != nil {
			exportErr = err
		}
		close(exportDone)
	}()

	foundCerts, err := certificate.FindCertificates(context.TODO(), r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to search for certificates in container image")
	}

	<-exportDone
	if exportErr != nil {
		return nil, errors.Wrap(err, "error when exporting image")
	}

	return foundCerts, nil
}
