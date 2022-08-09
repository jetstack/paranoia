package analyse

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	mathrand "math/rand"
	"testing"
	"time"
)

func TestAnalyser_AnalyseCertificate(t *testing.T) {
	// We don't use the NewAnalyser function, as that will do network access. Instead, construct an Analyser with a
	// predefined list of certificates.
	oneHourAgo := time.Now().Add(-time.Hour)
	// Okay, *approximately* one year. It doesn't matter if it's off by a few hours.
	inOneYear := time.Now().Add(time.Hour * 24 * 365)

	revokedCert, revokedFingerprint, err := generateTestCertificate(oneHourAgo, inOneYear)
	require.NoError(t, err)
	reasonString := "some string idk"
	analyser := Analyser{RemovedCertificates: []removedCertificate{
		{
			Fingerprint: revokedFingerprint,
			Comments:    reasonString,
		},
	}}

	t.Run("revoked certificate", func(t *testing.T) {
		notes := analyser.AnalyseCertificate(revokedCert)
		assert.Len(t, notes, 1)
		assert.Equal(t, NoteLevelError, notes[0].Level)
		assert.Contains(t, notes[0].Reason, "removed from Mozilla trust store")
		assert.Contains(t, notes[0].Reason, reasonString)
	})

	t.Run("expired certificate", func(t *testing.T) {
		expiredCert, _, err := generateTestCertificate(time.Now().Add(-time.Hour*2), time.Now().Add(-time.Hour))
		require.NoError(t, err)
		notes := analyser.AnalyseCertificate(expiredCert)
		assert.Len(t, notes, 1)
		assert.Equal(t, NoteLevelError, notes[0].Level)
		assert.Contains(t, notes[0].Reason, "expired")
	})

	t.Run("not yet valid certificate", func(t *testing.T) {
		expiredCert, _, err := generateTestCertificate(time.Now().Add(+time.Hour), inOneYear)
		require.NoError(t, err)
		notes := analyser.AnalyseCertificate(expiredCert)
		assert.Len(t, notes, 1)
		assert.Equal(t, NoteLevelError, notes[0].Level)
		assert.Contains(t, notes[0].Reason, "not yet valid")
	})

	t.Run("expiring soon", func(t *testing.T) {
		expiredCert, _, err := generateTestCertificate(time.Now().Add(-time.Hour*2), time.Now().Add(time.Hour))
		require.NoError(t, err)
		notes := analyser.AnalyseCertificate(expiredCert)
		assert.Len(t, notes, 1)
		assert.Equal(t, NoteLevelWarn, notes[0].Level)
		assert.Contains(t, notes[0].Reason, "expires soon")
	})
}

// generateTestCertificate will generate a random test certificate.
func generateTestCertificate(notBefore, notAfter time.Time) (*x509.Certificate, string, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(mathrand.Int())),
		Subject: pkix.Name{
			Organization: []string{"Jetstack"},
			Country:      []string{"UK"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, "", err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, "", err
	}
	return cert, fmt.Sprintf("%X", sha256.Sum256(cert.Raw)), nil
}
