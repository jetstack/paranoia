package image

import (
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Option is a functional option that configures image operations
type Option func(*options)

type options struct {
	craneOpts []crane.Option
}

func makeOptions(opts ...Option) *options {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	return o
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
