// SPDX-License-Identifier: Apache-2.0

package analyse

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"net/http"
	"time"

	"github.com/hako/durafmt"
)

type NoteLevel string

const (
	NoteLevelWarn     NoteLevel = "warn"
	NoteLevelError    NoteLevel = "error"
	fingerprintHeader           = "SHA-256 Fingerprint"
	commentsHeader              = "Comments"
)

type Note struct {
	Level  NoteLevel
	Reason string
}

type removedCertificate struct {
	Fingerprint string
	Comments    string
}

type Analyser struct {
	RemovedCertificates []removedCertificate
}

// NewAnalyser creates a new Analyzer using the public Mozilla CA removed certificate list as part of
// its checks. This method performs HTTP requests to retrieve that list. The request will be made with the given
// context.
func NewAnalyser() (*Analyser, error) {
	rc, err := downloadMozillaRemovedCACertsList()
	if err != nil {
		return nil, err
	}
	return &Analyser{RemovedCertificates: rc}, nil
}

func downloadMozillaRemovedCACertsList() ([]removedCertificate, error) {
	const mozillaRemovedCACertificateReportURL = "https://ccadb-public.secure.force.com/mozilla/RemovedCACertificateReportCSVFormat"

	resp, err := http.Get(mozillaRemovedCACertificateReportURL)
	if err != nil {
		return nil, err
	}
	csvReader := csv.NewReader(resp.Body)
	// Read the header first
	headers, err := csvReader.Read()
	if err != nil {
		return nil, err
	}

	// Find column indices by their names from the header
	fingerprint := -1
	comments := -1
	for idx, header := range headers {
		switch header {
		case fingerprintHeader:
			fingerprint = idx
		case commentsHeader:
			comments = idx
		}
	}

	if fingerprint == -1 {
		return nil, fmt.Errorf("required column 'SHA-256 Fingerprint' not found in CSV header")
	}
	if comments == -1 {
		return nil, fmt.Errorf("required column 'Comments' not found in CSV header")
	}

	// Now process each line individually instead of loading everything into memory
	var removedCerts []removedCertificate
	for {
		record, err := csvReader.Read()
		if err != nil {
			break // End of file or other error
		}

		removedCerts = append(removedCerts, removedCertificate{
			Fingerprint: record[fingerprint],
			Comments:    record[comments],
		})
	}

	// All CSV processing is done in the loop above, we already have the removedCerts slice
	return removedCerts, nil
}

// AnalyseCertificate takes an X.509 certificate and performs basic analysis. This is intended to highlight any concerns
// or issues to a user.
func (an *Analyser) AnalyseCertificate(cert *x509.Certificate) []Note {
	now := time.Now()
	sixIshMonthsFromNow := now.Add(time.Hour * 24 * 30 * 6)
	var notes []Note
	if now.Before(cert.NotBefore) {
		notes = append(notes, Note{
			Level:  NoteLevelError,
			Reason: "not yet valid ( becomes valid on " + cert.NotBefore.Format(time.RFC3339) + " in " + fmtDuration(cert.NotBefore.Sub(now)) + ")",
		})
	}
	if now.After(cert.NotAfter) {
		notes = append(notes, Note{
			Level:  NoteLevelError,
			Reason: "expired ( expired on " + cert.NotAfter.Format(time.RFC3339) + ", " + fmtDuration(now.Sub(cert.NotAfter)) + " since expiry)",
		})
	} else if sixIshMonthsFromNow.After(cert.NotAfter) {
		notes = append(notes, Note{
			Level:  NoteLevelWarn,
			Reason: "expires soon ( expires on " + cert.NotAfter.Format(time.RFC3339) + ", " + fmtDuration(cert.NotAfter.Sub(now)) + " until expiry)",
		})
	}
	fingerprint := fmt.Sprintf("%X", sha256.Sum256(cert.Raw))
	for _, rc := range an.RemovedCertificates {
		if fingerprint == rc.Fingerprint {
			reason := "removed from Mozilla trust store"
			if rc.Comments == "" {
				reason += ", no reason given"
			} else {
				reason += ", comments: " + rc.Comments
			}
			notes = append(notes, Note{
				Level:  NoteLevelError,
				Reason: reason,
			})
		}
	}
	return notes
}

func fmtDuration(duration time.Duration) string {
	return fmt.Sprint(durafmt.Parse(duration).LimitFirstN(2))
}
