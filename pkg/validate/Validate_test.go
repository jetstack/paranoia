package validate

import (
	"crypto/sha1"
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

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
			assert.Truef(t, r.IsPass(), "Validation reported as failed, expected pass")
		})

		t.Run("Accepts permitted certificates with SHA1", func(t *testing.T) {
			r, err := validator.Validate([]certificate.FoundCertificate{
				{
					FingerprintSha1:   checksum.MustParseSHA1(allowedSHA1),
					FingerprintSha256: anySHA256(),
				},
			})
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed, expected pass")
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

	t.Run("Permissive Allow List", func(t *testing.T) {
		validator, err := NewValidator(Config{}, true)
		require.NoError(t, err)

		certWeWant := certificate.FoundCertificate{
			FingerprintSha1:   checksum.MustParseSHA1("4749c6f4aeb2e06f6b71129a9697219e97166db4"),
			FingerprintSha256: checksum.MustParseSHA256("edfa7caf7f1274d54bacec91e21a5b1a04a7b94bf197f5c92070b8de148d9b37"),
		}

		r, err := validator.Validate([]certificate.FoundCertificate{certWeWant})
		assert.NoError(t, err)
		assert.Truef(t, r.IsPass(), "Validation reported failed, when we expected it to pass")
	})

	t.Run("Forbid List", func(t *testing.T) {
		forbiddenSHA1 := "4ae840b224dccf3af3ac0827be5f885eded18a17"
		forbiddenSHA256 := "01be162c36a6e26951a7ba4fbe6fba11dc7f4b9d589a072fc9d0183fc3386413"
		config := Config{
			Forbid: []CertificateEntry{
				{
					Fingerprints: CertificateFingerprints{
						Sha1: forbiddenSHA1,
					},
				},
				{
					Fingerprints: CertificateFingerprints{
						Sha256: forbiddenSHA256,
					},
				},
			},
		}

		validator, err := NewValidator(config, false)
		require.NoError(t, err)

		t.Run("Fails on forbidden SHA1", func(t *testing.T) {
			forbiddenCert := certificate.FoundCertificate{
				FingerprintSha1:   checksum.MustParseSHA1(forbiddenSHA1),
				FingerprintSha256: checksum.MustParseSHA256("edfa7caf7f1274d54bacec91e21a5b1a04a7b94bf197f5c92070b8de148d9b37"),
			}

			r, err := validator.Validate([]certificate.FoundCertificate{forbiddenCert})
			assert.NoError(t, err)
			assert.Falsef(t, r.IsPass(), "Validation reported passed, when expected it to fail")
			assert.Contains(t, r.ForbiddenCertificates, ForbiddenCert{Certificate: forbiddenCert, Entry: config.Forbid[0]})
		})

		t.Run("Fails on forbidden SHA256", func(t *testing.T) {
			forbiddenCert := certificate.FoundCertificate{
				FingerprintSha1:   checksum.MustParseSHA1("4749c6f4aeb2e06f6b71129a9697219e97166db4"),
				FingerprintSha256: checksum.MustParseSHA256(forbiddenSHA256),
			}

			r, err := validator.Validate([]certificate.FoundCertificate{forbiddenCert})
			assert.NoError(t, err)
			assert.Falsef(t, r.IsPass(), "Validation reported passed, when expected it to fail")
			assert.Contains(t, r.ForbiddenCertificates, ForbiddenCert{Certificate: forbiddenCert, Entry: config.Forbid[1]})
		})
	})

	t.Run("Fails when allowed SHA1 and forbidden SHA256", func(t *testing.T) {
		forbiddenSHA1 := "4ae840b224dccf3af3ac0827be5f885eded18a17"
		forbiddenSHA256 := "01be162c36a6e26951a7ba4fbe6fba11dc7f4b9d589a072fc9d0183fc3386413"
		config := Config{
			Allow: []CertificateEntry{
				{
					Fingerprints: CertificateFingerprints{
						Sha1: forbiddenSHA1,
					},
				},
			},
			Forbid: []CertificateEntry{
				{
					Fingerprints: CertificateFingerprints{
						Sha256: forbiddenSHA256,
					},
				},
			},
		}

		validator, err := NewValidator(config, false)
		require.NoError(t, err)

		forbiddenCert := certificate.FoundCertificate{
			FingerprintSha1:   checksum.MustParseSHA1(forbiddenSHA1),
			FingerprintSha256: checksum.MustParseSHA256(forbiddenSHA256),
		}

		r, err := validator.Validate([]certificate.FoundCertificate{forbiddenCert})
		assert.NoError(t, err)
		assert.Falsef(t, r.IsPass(), "Validation reported passed, when expected it to fail")
		assert.Contains(t, r.ForbiddenCertificates, ForbiddenCert{Certificate: forbiddenCert, Entry: config.Forbid[0]})
	})

	t.Run("Require List", func(t *testing.T) {
		requiredSHA1 := "4ae840b224dccf3af3ac0827be5f885eded18a17"
		requiredSHA256 := "01be162c36a6e26951a7ba4fbe6fba11dc7f4b9d589a072fc9d0183fc3386413"
		config := Config{
			Require: []CertificateEntry{
				{
					Fingerprints: CertificateFingerprints{
						Sha256: requiredSHA256,
					},
				},
				{
					Fingerprints: CertificateFingerprints{
						Sha1: requiredSHA1,
					},
				},
			},
		}

		validator, err := NewValidator(config, false)
		require.NoError(t, err)

		t.Run("All required certs found", func(t *testing.T) {
			foundCerts := []certificate.FoundCertificate{
				{FingerprintSha1: checksum.MustParseSHA1(requiredSHA1)},
				{FingerprintSha256: checksum.MustParseSHA256(requiredSHA256)},
			}

			r, err := validator.Validate(foundCerts)
			assert.NoError(t, err)
			assert.Truef(t, r.IsPass(), "Validation reported as failed, when we expected it to pass")
		})

		t.Run("Missing required cert", func(t *testing.T) {
			foundCert := certificate.FoundCertificate{
				FingerprintSha1:   anySHA1(),
				FingerprintSha256: anySHA256(),
			}

			r, err := validator.Validate([]certificate.FoundCertificate{foundCert})
			assert.NoError(t, err)
			assert.Falsef(t, r.IsPass(), "Validation reported as passed, when we expected it to fail")
			assert.Contains(t, r.RequiredButAbsent, CertificateEntry{Fingerprints: CertificateFingerprints{Sha1: requiredSHA1}})
			assert.Contains(t, r.RequiredButAbsent, CertificateEntry{Fingerprints: CertificateFingerprints{Sha256: requiredSHA256}})
		})

	})
}

func anySHA1() [20]byte {
	timestamp := time.Now().Unix()
	return sha1.Sum([]byte(strconv.FormatInt(timestamp, 10)))
}

func anySHA256() [32]byte {
	timestamp := time.Now().Unix()
	return sha256.Sum256([]byte(strconv.FormatInt(timestamp, 10)))
}
