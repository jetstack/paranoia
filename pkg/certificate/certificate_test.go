package certificate

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_openerForFile(t *testing.T) {
	t.Run("a large file should result in a file being written, which should be deleted when closed", func(t *testing.T) {
		unix := time.Now().Unix()
		name := fmt.Sprintf(" hello/world-file-%d ", unix)
		buf := bytes.NewReader([]byte("hello-world"))
		rsopener, closer, err := openerForFile(context.TODO(), &tar.Header{
			Name: name,
			Size: 999999999999999999,
		}, buf)
		require.NoError(t, err)

		dir, err := os.ReadDir(os.TempDir())
		require.NoError(t, err)

		var filename string
		for _, f := range dir {
			if strings.Contains(f.Name(), fmt.Sprintf("hello-world-file-%d", unix)) {
				filename = filepath.Join(os.TempDir(), f.Name())
				break
			}
		}
		require.NotEmpty(t, filename)

		b, err := os.ReadFile(filename)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello-world"), b)

		rs, err := rsopener()
		require.NoError(t, err)
		b, err = io.ReadAll(rs)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello-world"), b)

		assert.NoError(t, closer())
		assert.NoFileExists(t, filename)
	})

	t.Run("a small file should result in no file being written", func(t *testing.T) {
		unix := time.Now().Unix()
		name := fmt.Sprintf(" hello/world-file-%d ", unix)
		buf := bytes.NewReader([]byte("hello-world"))
		rsopener, closer, err := openerForFile(context.TODO(), &tar.Header{
			Name: name,
			Size: 10,
		}, buf)
		require.NoError(t, err)

		dir, err := os.ReadDir(os.TempDir())
		require.NoError(t, err)

		var filename string
		for _, f := range dir {
			if strings.Contains(f.Name(), fmt.Sprintf("hello-world-file-%d", unix)) {
				filename = filepath.Join(os.TempDir(), f.Name())
				break
			}
		}
		require.Empty(t, filename)

		rs, err := rsopener()
		require.NoError(t, err)
		b, err := io.ReadAll(rs)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello-world"), b)

		assert.NoError(t, closer())
		assert.NoFileExists(t, filename)
	})
}
