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
		Use:   "paranoia",
		Short: "Inspect container image trust bundles",
		Long:  `Paranoia is a CLI tool to inspect the trust bundles present in a container image.`,
	}

	root.AddCommand(newExport(ctx))
	root.AddCommand(newInspect(ctx))
	root.AddCommand(newValidation(ctx))

	return root
}

func Execute() {
	ctx := signals.SetupSignalHandler()
	if err := NewRoot(ctx).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
