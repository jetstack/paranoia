// SPDX-License-Identifier: Apache-2.0

package options

import "errors"

func MustSingleImageArgs(args []string) error {
	if len(args) != 1 {
		return errors.New("expected single image name argument")
	}

	return nil
}
