package validate

import (
	"encoding/hex"

	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/checksum"
)

type Validator struct {
	config         Config
	permissiveMode bool
	allowSHA1      map[[20]byte]bool
	allowSHA256    map[[32]byte]bool
	forbidSHA1     map[[20]byte]bool
	forbidSHA256   map[[32]byte]bool
	requiredSHA1   [][20]byte
	requiredSHA256 [][32]byte
}

func NewValidator(config Config, permissiveMode bool) (*Validator, error) {
	v := Validator{
		config:         config,
		permissiveMode: permissiveMode,
		allowSHA1:      make(map[[20]byte]bool),
		allowSHA256:    make(map[[32]byte]bool),
		forbidSHA1:     make(map[[20]byte]bool),
		forbidSHA256:   make(map[[32]byte]bool),
	}
	if !permissiveMode {
		for _, allowed := range config.Allow {
			if allowed.Fingerprints.Sha1 != "" {
				sha, err := checksum.ParseSHA1(allowed.Fingerprints.Sha1)
				if err != nil {
					return nil, err
				}
				v.allowSHA1[sha] = true
			}
			if allowed.Fingerprints.Sha256 != "" {
				sha, err := checksum.ParseSHA256(allowed.Fingerprints.Sha256)
				if err != nil {
					return nil, err
				}
				v.allowSHA256[sha] = true
			}
		}

		for _, required := range config.Require {
			if required.Fingerprints.Sha1 != "" {
				sha, err := checksum.ParseSHA1(required.Fingerprints.Sha1)
				if err != nil {
					return nil, err
				}
				v.allowSHA1[sha] = true
			}
			if required.Fingerprints.Sha256 != "" {
				sha, err := checksum.ParseSHA256(required.Fingerprints.Sha256)
				if err != nil {
					return nil, err
				}
				v.allowSHA256[sha] = true
			}
		}
	}

	for _, forbidden := range config.Forbid {
		if forbidden.Fingerprints.Sha1 != "" {
			sha, err := checksum.ParseSHA1(forbidden.Fingerprints.Sha1)
			if err != nil {
				return nil, err
			}
			v.forbidSHA1[sha] = true
		}
		if forbidden.Fingerprints.Sha256 != "" {
			sha, err := checksum.ParseSHA256(forbidden.Fingerprints.Sha256)
			if err != nil {
				return nil, err
			}
			v.forbidSHA256[sha] = true
		}
	}

	for _, required := range config.Require {
		if required.Fingerprints.Sha1 != "" {
			sha, err := checksum.ParseSHA1(required.Fingerprints.Sha1)
			if err != nil {
				return nil, err
			}
			v.requiredSHA1 = append(v.requiredSHA1, sha)
		}
		if required.Fingerprints.Sha256 != "" {
			sha, err := checksum.ParseSHA256(required.Fingerprints.Sha256)
			if err != nil {
				return nil, err
			}
			v.requiredSHA256 = append(v.requiredSHA256, sha)
		}
	}
	return &v, nil
}

type Result struct {
	NotAllowedCertificates []certificate.FoundCertificate
	ForbiddenCertificates  []certificate.FoundCertificate
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

		if v.IsForbidden(fc) {
			result.ForbiddenCertificates = append(result.ForbiddenCertificates, fc)
		}
	}

	// Check for missing required certificates
	for _, sha := range v.requiredSHA1 {
		if _, ok := sha1checksums[sha]; !ok {
			result.RequiredButAbsent = append(result.RequiredButAbsent, CertificateEntry{
				Fingerprints: CertificateFingerprints{
					Sha1: hex.EncodeToString(sha[:]),
				},
			})
		}
	}

	for _, sha := range v.requiredSHA256 {
		if _, ok := sha256checksums[sha]; !ok {
			result.RequiredButAbsent = append(result.RequiredButAbsent, CertificateEntry{
				Fingerprints: CertificateFingerprints{
					Sha256: hex.EncodeToString(sha[:]),
				},
			})
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

func (v *Validator) IsForbidden(fc certificate.FoundCertificate) bool {
	if _, ok := v.forbidSHA1[fc.FingerprintSha1]; ok {
		return true
	}

	if _, ok := v.forbidSHA256[fc.FingerprintSha256]; ok {
		return true
	}

	return false
}
