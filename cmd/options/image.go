// SPDX-License-Identifier: Apache-2.0

package options

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/jetstack/paranoia/internal/image"
)

// Image contains options for interacting with images
type Image struct {
	// Platform specifies the platform in the form
	// os/arch[/variant][:osversion] (e.g. linux/amd64)
	Platform string `json:"platform"`
}

// Options converts the options to a slice of image.Options
func (i *Image) Options() ([]image.Option, error) {
	var opts []image.Option

	if i.Platform != "" {
		platform, err := v1.ParsePlatform(i.Platform)
		if err != nil {
			return []image.Option{}, errors.Wrap(err, "parsing platform string")
		}
		opts = append(opts, image.WithPlatform(platform))
	}

	return opts, nil
}

// RegistryImage registers image options with cobra
func RegisterImage(cmd *cobra.Command) *Image {
	var opts Image
	cmd.Flags().StringVar(&opts.Platform, "platform", "", "Specifies the platform in the form os/arch[/variant][:osversion] (e.g. linux/amd64)")
	return &opts
}
