// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"os"
)

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect a container image for root certificates",
	Run: func(cmd *cobra.Command, args []string) {
		imageName := args[0]
		tmpfile, err := ioutil.TempFile("", "paranoia")
		if err != nil {
			log.Fatal(err)
		}

		defer func(name string) {
			err := os.Remove(name)
			if err != nil {
				log.Fatal(err)
			}
		}(tmpfile.Name())

		img, err := crane.Pull(imageName)
		if err != nil {
			log.Fatal(err)
		}

		err = crane.Export(img, tmpfile)
		if err != nil {
			log.Fatal(err)
		}

	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
