package validate

import (
	"errors"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

var ExpectedVersion = "1"

type Config struct {
	Version string             `json:"version"`
	Allow   []CertificateEntry `json:"allow"`
	Forbid  []CertificateEntry `json:"forbid"`
	Require []CertificateEntry `json:"require"`
}

type CertificateEntry struct {
	Fingerprints CertificateFingerprints `json:"fingerprints"`
}

type CertificateFingerprints struct {
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
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
