// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

func NewRoot(ctx context.Context) *cobra.Command {
	root := &cobra.Command{
		Use:   "paranoia subcommand",
		Short: "Inspect certificate authorities in container images ",
		Long: `
Paranoia is a command-line tool to inspect the certificate authorities present in a container image.
It is capable of scanning not only well-known locations (such as PEM-encoded files under /etc/ssl/certs/), but finding
certificates embedded in text files and even inside of binaries.

## LIMITATIONS

Paranoia will detect certificate authorities in most cases, and is especially useful at finding accidental inclusion or for conducting a certificate authority inventory. However there are some limitations to bear in mind while using Paranoia:

- Paranoia only functions on container images, not running containers.
  Anything added into the container at runtime is not seen.
- If a certificate is found, that doesn’t guarantee that the container will trust it as a certificate authority.
  It could, for example, be an unused leftover file.
- It’s possible for an attacker to ‘hide’ a certificate authority from Paranoia (e.g., by encoding it in a format Paranoia doesn’t understand).
  In general Paranoia isn’t designed to defend against an adversary with supply chain write access intentionally sneaking obfuscated certificate authorities into container images.

## CERTIFICATE DETECTION

Paranoia runs a number of parsers over the data contained within a container image.
This includes searching through files for strings, including binary files.

Container images are comprised of layers.
Each layer may remove or replace files from previous layers.
Paranoia only considers the final state of the image, available to the application at runtime.
Certificates in intermediate layers which are removed or replaced in later layers are not detected by Paranoia.

### Partial Certificates

Paranoia can also detect "partial" certificates.
A partial certificate is where Paranoia has detected data that appears to be a certificate but is incomplete or invalid.
These can be false-positives, but are often worthy of further investigation.

## LOCAL IMAGES

Paranoia can be invoked on any container image by name.
This can include a tag, or a SHA256 fingerprint.
Paranoia can also read from STDIN to handle local images that are exported as tar files.

To enable this behaviour, use "-" as the image name.

	$ docker save my-local-image:sometag | paranoia export -
`,
	}

	root.AddCommand(newExport(ctx))
	root.AddCommand(newInspect(ctx))
	root.AddCommand(newValidation(ctx))
	root.AddCommand(runController(ctx))

	return root
}

func Execute() {
	ctx := signals.SetupSignalHandler()
	if err := NewRoot(ctx).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
