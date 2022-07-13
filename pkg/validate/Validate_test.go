package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/checksum"
)

func TestValidator(t *testing.T) {

	t.Run("Non-Permissive Allow List", func(t *testing.T) {
		allowedSHA1 := "4ae840b224dccf3af3ac0827be5f885eded18a17"
		allowedSHA256 := "01be162c36a6e26951a7ba4fbe6fba11dc7f4b9d589a072fc9d0183fc3386413"
		config := Config{
			Allow: []CertificateEntry{
				{
					Fingerprints: CertificateFingerprints{
						Sha1: allowedSHA1,
					},
				},
				{
					Fingerprints: CertificateFingerprints{
						Sha256: allowedSHA256,
					},
				},
			},
		}

		validator, err := NewValidator(config, false)
		require.NoError(t, err)

		t.Run("No found certs is fine", func(t *testing.T) {
			r, err := validator.Validate(nil)
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed")
		})

		t.Run("Accepts permitted certificates with SHA1", func(t *testing.T) {
			r, err := validator.Validate([]certificate.FoundCertificate{
				{
					FingerprintSha1:   checksum.MustParseSHA1(allowedSHA1),
					FingerprintSha256: checksum.MustParseSHA256("edfa7caf7f1274d54bacec91e21a5b1a04a7b94bf197f5c92070b8de148d9b37"),
				},
			})
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed")
		})

		t.Run("Accepts permitted certificates with SHA256", func(t *testing.T) {
			r, err := validator.Validate([]certificate.FoundCertificate{
				{
					FingerprintSha1:   checksum.MustParseSHA1("673e582506961a8ebc133cb7890cee768501b84a"),
					FingerprintSha256: checksum.MustParseSHA256(allowedSHA256),
				},
			})
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed")
		})

		t.Run("Rejects other certificates", func(t *testing.T) {
			certWeDontWant := certificate.FoundCertificate{
				FingerprintSha1:   checksum.MustParseSHA1("4749c6f4aeb2e06f6b71129a9697219e97166db4"),
				FingerprintSha256: checksum.MustParseSHA256("edfa7caf7f1274d54bacec91e21a5b1a04a7b94bf197f5c92070b8de148d9b37"),
			}
			r, err := validator.Validate([]certificate.FoundCertificate{certWeDontWant})
			assert.NoError(t, err)
			assert.Falsef(t, r.IsPass(), "Validation reported as passed, when we expected it to fail")
			assert.Contains(t, r.NotAllowedCertificates, certWeDontWant)
		})
	})

}
