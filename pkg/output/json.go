package output

type JSONOutput struct {
	Certificates []JSONCertificate `json:"certificates"`
}

type JSONCertificate struct {
	FileLocation string `json:"fileLocation"`
	Owner        string `json:"owner"`
	Signature    string `json:"signature"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
}
