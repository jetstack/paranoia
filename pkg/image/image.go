// SPDX-License-Identifier: Apache-2.0

package image

import (
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func PullAndExport(imageName string, file *os.File) error {
	var img v1.Image
	if imageName == "-" {
		t, err := ioutil.TempFile("", "paranoia_stdin")
		if err != nil {
			return err
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				panic(err)
			}
			err = os.Remove(f.Name())
			if err != nil {
				panic(err)
			}
		}(t)

		_, err = io.Copy(t, os.Stdin)
		if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		img, err = crane.Load(t.Name())
		if err != nil {
			return err
		}
	} else if strings.HasPrefix(imageName, "file://") {
		var err error
		img, err = crane.Load(strings.TrimPrefix(imageName, "file://"))
		if err != nil {
			return err
		}
	} else {
		var err error
		img, err = crane.Pull(imageName)
		if err != nil {
			return err
		}
	}

	err := crane.Export(img, file)
	if err != nil {
		return err
	}

	return nil
}
