package output

type JSONOutput struct {
	Certificates []JSONCertificate `json:"certificates"`
}

type JSONCertificate struct {
	FileLocation      string `json:"fileLocation"`
	Owner             string `json:"owner"`
	Signature         string `json:"signature"`
	NotBefore         string `json:"notBefore"`
	NotAfter          string `json:"notAfter"`
	FingerprintSHA1   string `json:"FingerprintSHA1"`
	FingerprintSHA256 string `json:"FingerprintSHA256"`
}
