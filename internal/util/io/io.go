package io

import (
	"bytes"
	"io"
	"io/ioutil"
)

// Streams provides the standard names for iostreams.  This is useful for
// embedding and for unit testing.
// Inconsistent and different names make it hard to read and review code.
type Streams struct {
	// In think, os.Stdin
	In io.Reader
	// Out think, os.Stdout
	Out io.Writer
	// ErrOut think, os.Stderr
	ErrOut io.Writer
}

// NewTestStreams returns a valid Streams and in, out, errout buffers for unit
// tests
func NewTestStreams() (Streams, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	return Streams{
		In:     in,
		Out:    out,
		ErrOut: errOut,
	}, in, out, errOut
}

// NewTestStreamsDiscard returns a valid Streams that just discards
func NewTestStreamsDiscard() Streams {
	in := &bytes.Buffer{}
	return Streams{
		In:     in,
		Out:    ioutil.Discard,
		ErrOut: ioutil.Discard,
	}
}
