package image

import (
	"github.com/google/go-containerregistry/pkg/crane"
	"os"
)

func PullAndExport(imageName string, file *os.File) error {
	img, err := crane.Pull(imageName)
	if err != nil {
		return err
	}

	err = crane.Export(img, file)
	if err != nil {
		return err
	}

	return nil
}
