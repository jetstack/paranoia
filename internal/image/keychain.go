package image

import (
	"regexp"

	"github.com/google/go-containerregistry/pkg/authn"
)

// TokenAuthenticator implements authn.Authenticator using a bearer token
type TokenAuthenticator struct {
	Token string
}

func (a *TokenAuthenticator) Authorization() (*authn.AuthConfig, error) {
	return &authn.AuthConfig{
		Username: "oauth2accesstoken", // Required for GCR
		Password: a.Token,
	}, nil
}

// TokenKeychain matches only specific registries (e.g., GCR or Artifact Registry)
type TokenKeychain struct {
	Token      string
	Registries []*regexp.Regexp // regex patterns for registries
}

func (tk *TokenKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	for _, r := range tk.Registries {
		if r.MatchString(target.RegistryStr()) {
			return &TokenAuthenticator{Token: tk.Token}, nil
		}
	}
	return authn.Anonymous, nil
}
