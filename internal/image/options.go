package image

import (
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Option is a functional option for image operations.
type Option func(*options)

// options carries options for image operations.
type options struct {
	craneOpts []crane.Option
}

// makeOptions processes option functions and returns the resulting options.
func makeOptions(opts ...Option) *options {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// WithCraneOptions adds the given crane.Options to the image options.
func WithCraneOptions(craneOpts ...crane.Option) Option {
	return func(o *options) {
		o.craneOpts = append(o.craneOpts, craneOpts...)
	}
}

// WithPlatform is a functional option that configures the platform (i.e
// linux/amd64) images are resolved to.
func WithPlatform(platform *v1.Platform) Option {
	return func(o *options) {
		if platform != nil {
			o.craneOpts = append(o.craneOpts, crane.WithPlatform(platform))
		}
	}
}
