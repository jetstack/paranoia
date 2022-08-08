// SPDX-License-Identifier: Apache-2.0

package image

import (
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	crapi "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

var stdinTag name.Tag

func init() {
	var err error
	stdinTag, err = name.NewTag("stdin")
	if err != nil {
		panic("failed to build stdin tag: " + err.Error())
	}
}

func PullAndLoad(name string) (crapi.Image, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "-":
		return tarball.Image(func() (io.ReadCloser, error) { return os.Stdin, nil }, &stdinTag)
	case strings.HasPrefix(name, "file://"):
		return crane.Load(strings.TrimPrefix(name, "file://"))
	default:
		return crane.Pull(name)
	}
}
