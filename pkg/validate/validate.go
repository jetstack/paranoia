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

func NewValidator(config Config, permissveMode bool) (*Validator, error) {
	v := Validator{
		config:         config,
		permissiveMode: permissveMode,
		allowSHA1:      make(map[[20]byte]bool),
	}
	if !permissveMode {
		for _, allowed := range config.Allow {
			if allowed.Fingerprints.Sha1 != "" {
				sha, err := checksum.ParseSHA1(allowed.Fingerprints.Sha1)
				if err != nil {
					return nil, err
				}
				v.allowSHA1[sha] = true
			}
			// TODO the rest
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

	for _, fc := range certs {
		if !v.permissiveMode {
			// TODO Check we're on the allow list
			if _, ok := v.allowSHA1[fc.FingerprintSha1]; ok {
				// yay
			}
		}
		// TODO Check we're not on the forbid list
	}
	// TODO check this required cert is in the found list

	return &Result{}, nil
}
