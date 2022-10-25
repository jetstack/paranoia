// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"log"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/jetstack/paranoia/cmd"
)

func main() {
	header := &doc.GenManHeader{
		Section: "1",
	}
	const path = "man/"
	_ = os.RemoveAll(path)
	err := os.Mkdir(path, 0755)
	if err != nil {
		log.Fatal(err)
	}
	err = doc.GenManTree(cmd.NewRoot(context.Background()), header, path)
	if err != nil {
		log.Fatal(err)
	}
}
