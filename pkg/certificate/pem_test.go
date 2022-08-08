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
		file       string
		expReasons []string
	}{
		"simple certificate list should parse": {
			file: "testdata/test-1",
			expReasons: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=Google Internet Authority G2,O=Google Inc,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
			},
		},
		"certificate list if splattering of new lines should parse": {
			file: "testdata/test-2",
			expReasons: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=Google Internet Authority G2,O=Google Inc,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
			},
		},
		"certificate starts, but doesn't end should be picked up": {
			file: "testdata/test-3",
			expReasons: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"CN=Google Internet Authority G2,O=Google Inc,C=US",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
				"a block of data looks like a PEM certificate, but cannot be decoded",
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
			},
		},
		"malformed certificates should still be reported": {
			file: "testdata/test-4",
			expReasons: []string{
				"CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
				"failed to parse PEM certificate: x509: malformed certificate",
				"CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(test.file)
			require.NoError(t, err)

			resp, err := (pem{}).Find(context.TODO(), test.file, func() (io.ReadSeeker, error) {
				ff, err := io.ReadAll(f)
				if err != nil {
					return nil, err
				}
				return bytes.NewReader(ff), nil
			})

			assert.NoError(t, err)

			var reasons []string
			for _, r := range resp {
				assert.Equal(t, test.file, r.Location)
				reasons = append(reasons, r.Reason)
			}

			assert.Equal(t, test.expReasons, reasons)
		})
	}
}
