package cmd

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/pkg/errors"

	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/image"
)

func findImageCertificates(ctx context.Context, name string) ([]certificate.Found, error) {
	image, err := image.PullAndLoad(name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to pull and load image")
	}

	var exportErr error
	exportDone := make(chan struct{})
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		if err := crane.Export(image, w); err != nil {
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
