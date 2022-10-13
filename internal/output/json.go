// SPDX-License-Identifier: Apache-2.0

package output

type JSONOutput struct {
	Certificates        []JSONCertificate        `json:"certificates"`
	PartialCertificates []JSONPartialCertificate `json:"partials,omitempty"`
}

type JSONCertificate struct {
	FileLocation      string `json:"fileLocation"`
	Owner             string `json:"owner"`
	Parser            string `json:"parser"`
	Signature         string `json:"signature"`
	NotBefore         string `json:"notBefore"`
	NotAfter          string `json:"notAfter"`
	FingerprintSHA1   string `json:"fingerprintSHA1"`
	FingerprintSHA256 string `json:"fingerprintSHA256"`
}

type JSONPartialCertificate struct {
	FileLocation string `json:"fileLocation"`
	Reason       string `json:"reason"`
	Parser       string `json:"parser"`
}
