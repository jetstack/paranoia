// SPDX-License-Identifier: Apache-2.0

package image

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jetstack/paranoia/internal/certificate"
)

func TestFindImageCertificates_Platform(t *testing.T) {
	host := setupRegistry(t)

	// Create a multi-arch image and push it to the registry
	idx := makeTestIndex(
		t,
		map[string]v1.Image{
			"linux/amd64": makeTestImage(
				t,
				map[string]string{
					"linux-amd64.crt": "testdata/linux-amd64",
				},
			),
			"linux/arm64": makeTestImage(
				t,
				map[string]string{
					"linux-arm64.crt": "testdata/linux-arm64",
				},
			),
		},
	)
	idxTag := fmt.Sprintf("%s/%s:%s", host, "repo", "idx")
	idxRef, err := name.ParseReference(idxTag)
	if err != nil {
		t.Fatalf("unexpected error parsing reference: %s", err)
	}
	if err := remote.WriteIndex(idxRef, idx); err != nil {
		t.Fatalf("unexpected error writing index: %s", err)
	}

	// Push a lone image to the registry
	img := makeTestImage(
		t,
		map[string]string{
			"image.crt": "testdata/image",
		},
	)
	imgTag := fmt.Sprintf("%s/%s:%s", host, "repo", "tag")
	imgRef, err := name.ParseReference(imgTag)
	if err != nil {
		t.Fatalf("unexpected error parsing reference: %s", err)
	}
	if err := remote.Write(imgRef, img); err != nil {
		t.Fatalf("unexpected error writing index: %s", err)
	}

	testCases := map[string]func(t *testing.T){
		"default to linux/amd64 when no platform is set": func(t *testing.T) {
			gotCerts, err := FindImageCertificates(context.TODO(), idxTag)
			if err != nil {
				t.Fatalf("unexpected error finding certificates: %s", err)
			}

			wantCerts := &certificate.ParsedCertificates{
				Found: []certificate.Found{
					{
						Location: "/linux-amd64.crt",
						Parser:   "pem",
					},
				},
			}
			if diff := cmp.Diff(wantCerts, gotCerts, cmpopts.IgnoreFields(certificate.Found{}, "Certificate", "FingerprintSha1", "FingerprintSha256")); diff != "" {
				t.Fatalf("unexpected certificates:\n%s", diff)
			}
		},
		"return the correct image when linux/arm64 is set": func(t *testing.T) {
			platform, err := v1.ParsePlatform("linux/arm64")
			if err != nil {
				t.Fatalf("unexpected error parsing platform: %s", err)
			}
			gotCerts, err := FindImageCertificates(context.TODO(), idxTag, WithPlatform(platform))
			if err != nil {
				t.Fatalf("unexpected error finding certificates: %s", err)
			}

			wantCerts := &certificate.ParsedCertificates{
				Found: []certificate.Found{
					{
						Location: "/linux-arm64.crt",
						Parser:   "pem",
					},
				},
			}
			if diff := cmp.Diff(wantCerts, gotCerts, cmpopts.IgnoreFields(certificate.Found{}, "Certificate", "FingerprintSha1", "FingerprintSha256")); diff != "" {
				t.Fatalf("unexpected certificates:\n%s", diff)
			}

		},
		"a platform that doesn't have a manifest in the index should return an error": func(t *testing.T) {
			platform, err := v1.ParsePlatform("linux/386")
			if err != nil {
				t.Fatalf("unexpected error parsing platform: %s", err)
			}
			if _, err := FindImageCertificates(context.TODO(), idxTag, WithPlatform(platform)); err == nil {
				t.Fatalf("expected error but got nil")
			}
		},
		"the platform option should be ignored when the target is just an image": func(t *testing.T) {
			platform, err := v1.ParsePlatform("linux/arm64")
			if err != nil {
				t.Fatalf("unexpected error parsing platform: %s", err)
			}
			gotCerts, err := FindImageCertificates(context.TODO(), imgTag, WithPlatform(platform))
			if err != nil {
				t.Fatalf("unexpected error finding certificates: %s", err)
			}

			wantCerts := &certificate.ParsedCertificates{
				Found: []certificate.Found{
					{
						Location: "/image.crt",
						Parser:   "pem",
					},
				},
			}
			if diff := cmp.Diff(wantCerts, gotCerts, cmpopts.IgnoreFields(certificate.Found{}, "Certificate", "FingerprintSha1", "FingerprintSha256")); diff != "" {
				t.Fatalf("unexpected certificates:\n%s", diff)
			}
		},
	}

	for n, fn := range testCases {
		t.Run(n, fn)
	}
}

func makeTestImage(t *testing.T, fileMap map[string]string) v1.Image {
	m := map[string][]byte{}
	for path, f := range fileMap {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			t.Fatalf("unexpected error reading file: %s", err)
		}

		m[path] = data
	}

	img, err := crane.Image(m)
	if err != nil {
		t.Fatalf("unexpected error creating image: %s", err)
	}

	return img
}

func makeTestIndex(t *testing.T, imgs map[string]v1.Image) v1.ImageIndex {
	manifest := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{},
	}

	images := make(map[v1.Hash]v1.Image)
	for platform, img := range imgs {
		p, err := v1.ParsePlatform(platform)
		if err != nil {
			t.Fatalf("unexpected error parsing platform: %s", err)
		}

		rawManifest, err := img.RawManifest()
		if err != nil {
			t.Fatalf("unexpected error getting raw manifest: %s", err)
		}
		digest, size, err := v1.SHA256(bytes.NewReader(rawManifest))
		if err != nil {
			t.Fatalf("unexpected error getting digest: %s", err)
		}
		mediaType, err := img.MediaType()
		if err != nil {
			t.Fatalf("unexpected error getting media type: %s", err)
		}

		manifest.Manifests = append(manifest.Manifests, v1.Descriptor{
			Digest:    digest,
			Size:      size,
			MediaType: mediaType,
			Platform:  p,
		})

		images[digest] = img
	}

	return &testIndex{
		images:   images,
		manifest: &manifest,
	}
}

type testIndex struct {
	images   map[v1.Hash]v1.Image
	manifest *v1.IndexManifest
}

func (i *testIndex) MediaType() (types.MediaType, error) {
	return i.manifest.MediaType, nil
}

func (i *testIndex) Digest() (v1.Hash, error) {
	return partial.Digest(i)
}

func (i *testIndex) Size() (int64, error) {
	return partial.Size(i)
}

func (i *testIndex) IndexManifest() (*v1.IndexManifest, error) {
	return i.manifest, nil
}

func (i *testIndex) RawManifest() ([]byte, error) {
	m, err := i.IndexManifest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func (i *testIndex) Image(h v1.Hash) (v1.Image, error) {
	if img, ok := i.images[h]; ok {
		return img, nil
	}

	return nil, fmt.Errorf("image not found: %v", h)
}

func (i *testIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	return nil, fmt.Errorf("image not found: %v", h)
}

func setupRegistry(t *testing.T) string {
	r := httptest.NewServer(registry.New())
	t.Cleanup(r.Close)
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatalf("unexpected error parsing registry url: %s", err)
	}
	return u.Host
}
