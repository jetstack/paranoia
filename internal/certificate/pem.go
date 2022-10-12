// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	encpem "encoding/pem"
	"errors"
	"fmt"
	"io"
)

type pem struct{}

// Find finds X.509 PEM encoded certificates in the given reader. It does this
// by greping through the input and attempting to find the PEM Certificate
// header. Once found, it attempts to find the end footer. Even if the end
// footer is not found, a Certificate is still recorded, but marked as not
// correctly decoded.
func (_ pem) Find(ctx context.Context, location string, rs rseekerOpener) (*ParsedCertificates, error) {
	ignored := []byte{'\n', '\t', '\r', ' ', '\f', '\v', '\b', '\x00', '"', '\''}
	pemStart := []byte("-----BEGIN CERTIFICATE-----")
	pemEnd := []byte("-----END CERTIFICATE-----")

	file, err := rs()
	if err != nil {
		return nil, err
	}

	var (
		// token is the single token buffer we use to scan each file.
		token = make([]byte, 1)
		// results is the end result of the found certificates for this file
		// location.
		results []Found
		// partials is the list of partial certificates found
		partials []Partial
		// Current is the current successfully decoded certificate buffer. Starts
		// empty until we start to scan with a successful header.
		current []byte
	)
	for {
		// Read a single token from the file. Exit scanning if we reach the end of
		// the file.
		_, err := file.Read(token)
		if errors.Is(err, io.EOF) {
			break
		}

		// Exit if we encounter an error reading from file.
		if err != nil {
			return nil, err
		}

		// If  context has been cancelled, exit scanning.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// We ignore space tokens so allow for correctly scanning malformed
		// certificates.
		if bytes.Contains(ignored, token) {
			continue
		}

		if token[0] == pemStart[len(current)] {
			// If the scanned token matches the current PEM start token, we append to
			// the current.
			current = append(current, token[0])
		} else {
			// Did not match, reset current to empty.
			current = current[:0]
		}

		if len(current) == 10 {
			// Make sure we add the space character from PEM start since those get
			// ignored.
			current = append(current, ' ')
		}

		// If we have the PEM header, then we can start to scan for the footer.
		if len(current) == len(pemStart) {
			// footer is the buffer we use to match on the PEM footer.
			var footer []byte

			for {
				// Check errors and return/break appropriately.
				_, err := file.Read(token)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return nil, err
				}

				// Again, check context.
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				default:
				}

				// continue for ignored characters.
				if bytes.Contains(ignored, token) {
					// Append if we haven't reached the footer yet, or need to add the
					// space character.
					if len(footer) == 0 || len(footer) == 9 {
						current = append(current, token[0])
					}
					continue
				}

				// Always append to current to catch all certificate data.
				current = append(current, token[0])

				// Check for PEM footer character, or reset footer.
				if token[0] == pemEnd[len(footer)] {
					footer = append(footer, token[0])
				} else {
					footer = footer[:0]
				}

				// Add in the space character we ignore.
				if len(footer) == 8 {
					footer = append(footer, ' ')
				}

				// If the length of footer matches the PEM footer, then we have scanned
				// a certificate.
				if len(footer) == len(pemEnd) {
					//current = append(current, footer...)
					break
				}
			}

			// Here we stopped scanning for the footer. This might be because we got
			// to the end of the file, or we matched on the footer.

			var (
				valid    = false
				reason   string
				cert     *x509.Certificate
				fpsha1   [20]byte
				fpsha256 [32]byte
			)

			// If we did match on the footer, then attempt to decode the actual
			// certificate.
			if len(footer) == len(pemEnd) {
				block, _ := encpem.Decode(current)

				if block == nil {
					reason = fmt.Sprintf("a block of data looks like a PEM certificate, but cannot be decoded")
				} else {
					cert, err = x509.ParseCertificate(block.Bytes)
					if err != nil {
						reason = fmt.Sprintf("failed to parse PEM certificate: %s", err)
					} else {
						fpsha1 = sha1.Sum(block.Bytes)
						fpsha256 = sha256.Sum256(block.Bytes)
						valid = true
					}
				}
			} else {
				// If we didn't actually decode an entire certificate, then set an
				// appropriate reason, and reset the file so we can re-scan.
				reason = "found start of PEM encoded certificate, but could not find end"
				if _, err := file.Seek(-int64(len(current)-len(pemStart)+1), io.SeekCurrent); err != nil {
					return nil, fmt.Errorf("failed to seek: %w", err)
				}
			}

			// Capture result.
			if valid {
				results = append(results, Found{
					Location:          location,
					Parser:            "pem",
					Certificate:       cert,
					FingerprintSha1:   fpsha1,
					FingerprintSha256: fpsha256,
				})
			} else {
				partials = append(partials, Partial{
					Location: location,
					Parser:   "pem",
					Reason:   reason,
				})
			}
			current = current[:0]
		}
	}

	return &ParsedCertificates{
		Found:    results,
		Partials: partials,
	}, nil
}
