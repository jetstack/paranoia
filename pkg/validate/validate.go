package validate

import (
	"github.com/jetstack/paranoia/pkg/certificate"
	"github.com/jetstack/paranoia/pkg/checksum"
)

type Issue struct {
	Certificate certificate.FoundCertificate
}

type Validator struct {
	config         Config
	permissiveMode bool
	allowSHA1      map[[20]byte]bool
	allowSHA256    map[[32]byte]bool
	forbidSHA1     map[[20]byte]bool
	forbidSHA256   map[[32]byte]bool
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
	for _, fc := range certs {
		if !v.permissiveMode {
			if !v.IsAllowed(fc) {
				result.NotAllowedCertificates = append(result.NotAllowedCertificates, fc)
			}
		}
		if v.IsForbidden(fc) {
			result.ForbiddenCertificates = append(result.ForbiddenCertificates, fc)
		}
	}
	// TODO check this required cert is in the found list

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
