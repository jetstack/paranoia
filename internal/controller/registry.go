package controller

import (
	"context"
	"fmt"

	"github.com/jetstack/paranoia/internal/api"
	"github.com/jetstack/paranoia/internal/client"
	"github.com/sirupsen/logrus"
)

type Version struct {
	log *logrus.Entry

	client client.ClientHandler
}

func New(log *logrus.Entry, client client.ClientHandler) *Version {
	log = log.WithField("module", "version_getter")

	v := &Version{
		log:    log,
		client: client,
	}

	return v
}

// Fetch returns the given image tags for a given image URL.
func (v *Version) Fetch(ctx context.Context, imageURL string, _ *api.Options) (interface{}, error) {
	// fetch tags from image URL
	tags, err := v.client.Tags(ctx, imageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from remote registry for %q: %s",
			imageURL, err)
	}

	// respond with no version found if no manifests were found to prevent
	// needlessly querying a bad URL.
	if len(tags) == 0 {
		return nil, err
	}
	v.log.WithField("image", imageURL).Debugf("fetched %v tags", len(tags))

	return tags, nil
}
