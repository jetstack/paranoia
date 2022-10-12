package certificate

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_x509pem(t *testing.T) {
	tests := map[string]struct {
		file              string
		expSubjects       []string
		expPartialReasons []string
	}{
		"simple certificate list should parse": {
			file: "testdata/test-1",
			expSubjects: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=Google Internet Authority G2,O=Google Inc,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
			},
		},
		"certificate list if splattering of new lines should parse": {
			file: "testdata/test-2",
			expSubjects: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=Google Internet Authority G2,O=Google Inc,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
			},
		},
		"certificate starts, but doesn't end should be picked up": {
			file: "testdata/test-3",
			expSubjects: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=Google Internet Authority G2,O=Google Inc,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
			},
			expPartialReasons: []string{
				"a block of data looks like a PEM certificate, but cannot be decoded",
			},
		},
		"malformed certificates should still be reported": {
			file: "testdata/test-4",
			expSubjects: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
			},
			expPartialReasons: []string{
				"failed to parse PEM certificate: x509: malformed certificate",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(test.file)
			require.NoError(t, err)

			parsedCerts, err := (pem{}).Find(context.TODO(), test.file, func() (io.ReadSeeker, error) {
				ff, err := io.ReadAll(f)
				if err != nil {
					return nil, err
				}
				return bytes.NewReader(ff), nil
			})

			assert.NoError(t, err)

			var subjects []string
			for _, r := range parsedCerts.Found {
				assert.Equal(t, test.file, r.Location)
				subjects = append(subjects, r.Certificate.Subject.String())
			}
			assert.ElementsMatch(t, test.expSubjects, subjects)

			var partialsReasons []string
			for _, r := range parsedCerts.Partials {
				assert.Equal(t, test.file, r.Location)
				partialsReasons = append(partialsReasons, r.Reason)
			}
			assert.ElementsMatch(t, test.expPartialReasons, partialsReasons)
		})
	}
}
