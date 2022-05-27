// SPDX-License-Identifier: Apache-2.0

package analyse

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"github.com/hako/durafmt"
	"net/http"
	"time"
)

type NoteLevel string

const (
	NoteLevelWarn  = "warn"
	NoteLevelError = "error"
)

type Note struct {
	Level  NoteLevel
	Reason string
}

type RemovedCertificate struct {
	Fingerprint string
	Comments    string
}

type Analyser struct {
	RemovedCertificates []RemovedCertificate
}

func NewAnalyser() (*Analyser, error) {
	resp, err := http.Get("https://ccadb-public.secure.force.com/mozilla/RemovedCACertificateReportCSVFormat")
	if err != nil {
		return nil, err
	}

	csvReader := csv.NewReader(resp.Body)
	rc, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	a := Analyser{RemovedCertificates: make([]RemovedCertificate, len(rc))}

	for i, c := range rc {
		a.RemovedCertificates[i] = RemovedCertificate{
			Fingerprint: c[7],
			Comments:    c[22],
		}
	}
	return &a, nil
}

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
