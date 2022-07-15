// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
)

var ExpectedVersion = "1"

type Config struct {
	Version string             `json:"version"`
	Allow   []CertificateEntry `json:"allow,omitempty"`
	Forbid  []CertificateEntry `json:"forbid,omitempty"`
	Require []CertificateEntry `json:"require,omitempty"`
}

type CertificateEntry struct {
	Fingerprints CertificateFingerprints `json:"fingerprints"`
	Comment      string                  `json:"comment,omitempty"`
}

type CertificateFingerprints struct {
	Sha1   string `json:"sha1,omitempty"`
	Sha256 string `json:"sha256,omitempty"`
}

func LoadConfig(fileName string) (*Config, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	var contents map[string]interface{}
	err = yaml.Unmarshal(b, &contents)
	if err != nil {
		return nil, err
	}
	if contents["version"].(string) != ExpectedVersion {
		return nil, errors.New("Unsupported config version, expected " + ExpectedVersion + ", found" + contents["version"].(string))
	}

	var c Config
	err = yaml.Unmarshal(b, &c)
	return &c, err
}

func stderr(s string) {
	_, err := fmt.Fprintln(os.Stderr, s)
	if err != nil {
		panic(err)
	}
}

func IsConfigValid(config *Config) bool {
	isValid := true
	for _, list := range []struct {
		list []CertificateEntry
		name string
	}{
		{
			list: config.Allow,
			name: "allow",
		},
		{
			list: config.Forbid,
			name: "forbid",
		},
		{
			list: config.Require,
			name: "require",
		},
	} {
		for i, ce := range list.list {
			f := ce.Fingerprints
			if f.Sha1 == "" && f.Sha256 == "" {
				isValid = false
				stderr(fmt.Sprintf("Entry at position %d in %s list has no fingerprints. A fingerprint is required to identify the certificate.", i, list.name))
			} else if f.Sha1 != "" && f.Sha256 != "" {
				isValid = false
				stderr(fmt.Sprintf("Entry at position %d in %s list has both SHA1 and SHA256 fingerprints. Only one type of fingerprint is permitted on a certificate.", i, list.name))
			}
		}
	}
	return isValid
}
