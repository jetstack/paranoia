package output

import (
	"errors"
	"strings"
)

const (
	ModePretty = "pretty"
	ModeJSON   = "json"
)

var Modes = []string{ModePretty, ModeJSON}

func ValidateOutputMode(om string) error {
	for _, m := range Modes {
		if om == m {
			return nil
		}
	}
	return errors.New("invalid output mode, must be one of " + strings.Join(Modes, ", "))
}
