// SPDX-License-Identifier: Apache-2.0

package analyse

import (
	"crypto/x509"
	"fmt"
	"github.com/hako/durafmt"
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

func AnalyseCertificate(cert *x509.Certificate) []Note {
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
	return notes
}

func fmtDuration(duration time.Duration) string {
	return fmt.Sprint(durafmt.Parse(duration).LimitFirstN(2))
}
