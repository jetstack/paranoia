package validate

import (
	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/checksum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidator(t *testing.T) {

	t.Run("Non-Permissive Allow List", func(t *testing.T) {
		allowedSHA1 := "4ae840b224dccf3af3ac0827be5f885eded18a17"
		config := Config{
			Allow: []CertificateEntry{
				{
					Fingerprints: CertificateFingerprints{
						Sha1: allowedSHA1,
					},
				},
				{
					Fingerprints: CertificateFingerprints{
						Sha256: "01be162c36a6e26951a7ba4fbe6fba11dc7f4b9d589a072fc9d0183fc3386413",
					},
				},
			},
		}

		validator, err := NewValidator(config, false)
		require.NoError(t, err)

		t.Run("No certs is fine", func(t *testing.T) {
			r, err := validator.Validate(nil)
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed")
		})

		t.Run("Accepts permitted certificates", func(t *testing.T) {
			sha, err := checksum.ParseSHA1(allowedSHA1)
			require.NoError(t, err)
			r, err := validator.Validate([]certificate.FoundCertificate{
				{
					FingerprintSha1: sha,
				},
			})
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed")
		})

		t.Run("Rejects other certificates", func(t *testing.T) {
			sha, err := checksum.ParseSHA1("4749c6f4aeb2e06f6b71129a9697219e97166db4")
			require.NoError(t, err)

			certWeDontWant := certificate.FoundCertificate{
				FingerprintSha1: sha,
			}
			r, err := validator.Validate([]certificate.FoundCertificate{certWeDontWant})
			assert.NoError(t, err)
			assert.Falsef(t, r.IsPass(), "Validation reported as passed, when we expected it to fail")
			assert.Contains(t, r.NotAllowedCertificates, certWeDontWant)
		})
	})

}
