package io

// File: internal/io/tail_reader.go
// This file provides a TailReader that reads the last N bytes from an io.Reader.

import (
	"io"
)

type TailReader struct {
	r       io.Reader
	buf     []byte // ring buffer for tail
	size    int    // N
	readEOF bool
	queue   []byte // data that can still be read by consumer
}

// NewTailReader wraps r so that the last size bytes are withheld.
func NewTailReader(r io.Reader, size int) *TailReader {
	return &TailReader{
		r:    r,
		buf:  make([]byte, 0, size),
		size: size,
	}
}

func (tr *TailReader) Read(p []byte) (int, error) {
	// Fill from underlying reader
	for len(tr.queue) < len(p) && !tr.readEOF {
		tmp := make([]byte, max(3*tr.size, 4096)) // Read more than needed to ensure we have enough data
		n, err := tr.r.Read(tmp)
		if n > 0 {
			data := tmp[:n]
			// append to buf
			tr.buf = append(tr.buf, data...)
			// split: part to keep as tail, part to expose
			if len(tr.buf) > tr.size {
				excess := tr.buf[:len(tr.buf)-tr.size]
				tr.queue = append(tr.queue, excess...)
				tr.buf = tr.buf[len(tr.buf)-tr.size:]
			}
		}
		if err == io.EOF {
			tr.readEOF = true
		} else if err != nil {
			return 0, err
		}
	}

	if len(tr.queue) == 0 {
		if tr.readEOF {
			return 0, io.EOF
		}
		return 0, nil
	}

	n := copy(p, tr.queue)
	tr.queue = tr.queue[n:]
	return n, nil
}

// Tail returns the last N bytes after the stream is consumed.
func (tr *TailReader) Tail() ([]byte, error) {
	if !tr.readEOF {
		// force read underlying until EOF
		_, _ = io.Copy(io.Discard, tr)
	}
	if len(tr.buf) < tr.size {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), tr.buf...), nil
}
