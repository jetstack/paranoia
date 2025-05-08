// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	crapi "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/pkg/errors"

	"github.com/jetstack/paranoia/internal/certificate"
)

// QuayAuthenticator implements the authn.Authenticator interface for quay.io
type QuayAuthenticator struct {
	Username string
	Password string
}

// Authorization returns the authentication header for quay.io
func (q *QuayAuthenticator) Authorization() (*authn.AuthConfig, error) {
	return &authn.AuthConfig{
		Username: q.Username,
		Password: q.Password,
	}, nil
}

type quayKeychain struct {
	auth authn.Authenticator
}

func (q *quayKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if target.RegistryStr() == "quay.io" {
		return q.auth, nil
	}
	return authn.Anonymous, nil
}

// Custom keychain that only returns ECR creds for ECR domains
type ecrKeychain struct {
	delegate authn.Keychain
}

func (ek *ecrKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	// Only match ECR domains
	if strings.HasSuffix(target.RegistryStr(), ".amazonaws.com") {
		return ek.delegate.Resolve(target)
	}
	return authn.Anonymous, nil
}

// FindImageCertificates will pull or load the image with the given name, scan
// for X.509 certificates, and return the result.
func FindImageCertificates(ctx context.Context, name string, opts ...Option) (*certificate.ParsedCertificates, error) {
	o := makeOptions(opts...)

	name = strings.TrimSpace(name)

	var quayAuth authn.Authenticator = authn.Anonymous
	if username, password := os.Getenv("QUAY_USERNAME"), os.Getenv("QUAY_PASSWORD"); username != "" && password != "" {
		quayAuth = &QuayAuthenticator{
			Username: username,
			Password: password,
		}
	}

	quayKeychain := &quayKeychain{auth: quayAuth}

	// ECR Helper
	ecrHelper := ecr.NewECRHelper()

	kc := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		&ecrKeychain{delegate: authn.NewKeychainFromHelper(ecrHelper)},
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
		quayKeychain,
	)

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

		img, err = crane.Load(f.Name(), o.craneOpts...)
	case strings.HasPrefix(name, "file://"):
		img, err = crane.Load(strings.TrimPrefix(name, "file://"), o.craneOpts...)
	default:
		img, err = crane.Pull(name, append(o.craneOpts, crane.WithAuthFromKeychain(kc))...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load image: %w", err)
	}

	// Ensure cleanup of image resources
	defer func() {
		if img != nil {
			if c, ok := img.(interface{ Close() error }); ok {
				_ = c.Close()
			}
			if c, ok := img.(interface{ Cleanup() error }); ok {
				_ = c.Cleanup()
			}
		}
	}()

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

	parsedCertificates, err := certificate.FindCertificates(context.TODO(), r)
	if err != nil {
		// Ensure cleanup of image resources before returning
		if img != nil {
			if c, ok := img.(interface{ Close() error }); ok {
				_ = c.Close()
			}
			if c, ok := img.(interface{ Cleanup() error }); ok {
				_ = c.Cleanup()
			}
		}
		return nil, errors.Wrap(err, "failed to search for certificates in container image")
	}

	<-exportDone
	if exportErr != nil {
		// Ensure cleanup of image resources before returning
		if img != nil {
			if c, ok := img.(interface{ Close() error }); ok {
				_ = c.Close()
			}
			if c, ok := img.(interface{ Cleanup() error }); ok {
				_ = c.Cleanup()
			}
		}
		return nil, errors.Wrap(err, "error when exporting image")
	}

	// Ensure cleanup of image resources after successful processing
	if img != nil {
		if c, ok := img.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		if c, ok := img.(interface{ Cleanup() error }); ok {
			_ = c.Cleanup()
		}
	}

	return parsedCertificates, nil
}
