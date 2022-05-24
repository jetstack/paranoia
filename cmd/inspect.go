// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/nlepage/go-tarfs"
	"github.com/spf13/cobra"
	"io/fs"
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
		err = tmpfile.Close()
		if err != nil {
			log.Fatal(err)
		}

		f, err := os.Open(tmpfile.Name())
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				log.Fatal(err)
			}
		}(f)

		tfs, err := tarfs.New(f)
		if err != nil {
			log.Fatal(err)
		}

		err = fs.WalkDir(tfs, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(path)
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Done")
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
