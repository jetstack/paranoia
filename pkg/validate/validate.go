package validate

import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"

	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/checksum"
)

type Validator struct {
	config         Config
	permissiveMode bool
	allowSHA1      map[[20]byte]bool
	allowSHA256    map[[32]byte]bool
	forbidSHA1     map[[20]byte]CertificateEntry
	forbidSHA256   map[[32]byte]CertificateEntry
	required       []CertificateEntry
}

func (v *Validator) DescribeConfig() string {
	s := fmt.Sprintf("%d allowed, %d forbidden, and %d required certificates",
		len(v.allowSHA1)+len(v.allowSHA256),
		len(v.forbidSHA1)+len(v.forbidSHA256),
		len(v.required))
	if v.permissiveMode {
		s += ", in permissive mode"
	} else {
		s += ", in strict mode"
	}
	return s
}

func NewValidator(config Config, permissiveMode bool) (*Validator, error) {
	if !IsConfigValid(&config) {
		return nil, fmt.Errorf("invalid validator config")
	}
	v := Validator{
		config:         config,
		permissiveMode: permissiveMode,
		allowSHA1:      make(map[[20]byte]bool),
		allowSHA256:    make(map[[32]byte]bool),
		forbidSHA1:     make(map[[20]byte]CertificateEntry),
		forbidSHA256:   make(map[[32]byte]CertificateEntry),
		required:       config.Require,
	}
	if !permissiveMode {
		for i, allowed := range config.Allow {
			if allowed.Fingerprints.Sha256 != "" {
				sha, err := checksum.ParseSHA256(allowed.Fingerprints.Sha256)
				if err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("entry at position %d in allow list had invalid SHA256", i))
				}
				v.allowSHA256[sha] = true
			} else if allowed.Fingerprints.Sha1 != "" {
				sha, err := checksum.ParseSHA1(allowed.Fingerprints.Sha1)
				if err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("entry at position %d in allow list had invalid SHA1", i))
				}
				v.allowSHA1[sha] = true
			}
		}

		for i, required := range config.Require {
			if required.Fingerprints.Sha256 != "" {
				sha, err := checksum.ParseSHA256(required.Fingerprints.Sha256)
				if err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("entry at position %d in require list had invalid SHA256", i))
				}
				v.allowSHA256[sha] = true
			} else if required.Fingerprints.Sha1 != "" {
				sha, err := checksum.ParseSHA1(required.Fingerprints.Sha1)
				if err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("entry at position %d in require list had invalid SHA1", i))
				}
				v.allowSHA1[sha] = true
			}

		}
	}

	for i, forbidden := range config.Forbid {
		if forbidden.Fingerprints.Sha256 != "" {
			sha, err := checksum.ParseSHA256(forbidden.Fingerprints.Sha256)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("entry at position %d in forbid list had invalid SHA256", i))
			}
			v.forbidSHA256[sha] = forbidden
		} else if forbidden.Fingerprints.Sha1 != "" {
			sha, err := checksum.ParseSHA1(forbidden.Fingerprints.Sha1)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("entry at position %d in forbid list had invalid SHA1", i))
			}
			v.forbidSHA1[sha] = forbidden
		}
	}
	return &v, nil
}

type ForbiddenCert struct {
	Certificate certificate.FoundCertificate
	Entry       CertificateEntry
}

type Result struct {
	NotAllowedCertificates []certificate.FoundCertificate
	ForbiddenCertificates  []ForbiddenCert
	RequiredButAbsent      []CertificateEntry
}

func (r *Result) IsPass() bool {
	return r != nil && len(r.ForbiddenCertificates) == 0 && len(r.NotAllowedCertificates) == 0 && len(r.RequiredButAbsent) == 0
}

func (v *Validator) Validate(certs []certificate.FoundCertificate) (*Result, error) {
	result := Result{}
	sha1checksums := make(map[[20]byte]bool)
	sha256checksums := make(map[[32]byte]bool)
	for _, fc := range certs {
		sha1checksums[fc.FingerprintSha1] = true
		sha256checksums[fc.FingerprintSha256] = true
		if !v.permissiveMode {
			if !v.IsAllowed(fc) {
				result.NotAllowedCertificates = append(result.NotAllowedCertificates, fc)
			}
		}

		if b, ce := v.IsForbidden(fc); b {
			result.ForbiddenCertificates = append(result.ForbiddenCertificates, ForbiddenCert{
				Certificate: fc,
				Entry:       *ce,
			})
		}
	}

	// Check for missing required certificates
	for _, required := range v.required {
		if required.Fingerprints.Sha256 != "" {
			s, err := checksum.ParseSHA256(required.Fingerprints.Sha256)
			if err != nil {
				return nil, err
			}
			if _, ok := sha256checksums[s]; !ok {
				result.RequiredButAbsent = append(result.RequiredButAbsent, CertificateEntry{
					Fingerprints: CertificateFingerprints{
						Sha1: hex.EncodeToString(s[:]),
					},
				})
			}
		} else if required.Fingerprints.Sha1 != "" {
			s, err := checksum.ParseSHA1(required.Fingerprints.Sha1)
			if err != nil {
				return nil, err
			}
			if _, ok := sha1checksums[s]; !ok {
				result.RequiredButAbsent = append(result.RequiredButAbsent, CertificateEntry{
					Fingerprints: CertificateFingerprints{
						Sha1: hex.EncodeToString(s[:]),
					},
				})
			}
		}
	}

	return &result, nil
}

func (v *Validator) IsAllowed(fc certificate.FoundCertificate) bool {
	if _, ok := v.allowSHA1[fc.FingerprintSha1]; ok {
		return true
	}

	if _, ok := v.allowSHA256[fc.FingerprintSha256]; ok {
		return true
	}

	return false
}

func (v *Validator) IsForbidden(fc certificate.FoundCertificate) (bool, *CertificateEntry) {
	if ce, ok := v.forbidSHA1[fc.FingerprintSha1]; ok {
		return true, &ce
	}

	if ce, ok := v.forbidSHA256[fc.FingerprintSha256]; ok {
		return true, &ce
	}

	return false, nil
}
