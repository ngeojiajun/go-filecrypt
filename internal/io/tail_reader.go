package io

// File: internal/io/tail_reader.go
// This file provides a TailReader that reads the last N bytes from an io.Reader.

import (
	"io"
)

type TailReader struct {
	r                  io.Reader
	buf                []byte // ring buffer for tail
	size               int    // N
	readEOF            bool
	queue              []byte // data that can still be read by consumer
	readHead, fillHead int
}

// NewTailReader wraps r so that the last size bytes are withheld.
func NewTailReader(r io.Reader, size int) *TailReader {
	return NewTailReaderWithBuffer(r, size, make([]byte, max(size, 3*4096)))
}

// NewTailReaderWithBuffer wraps r so that the last size bytes are withheld.
// It allows the caller to provide a buffer for the queue to prevent sensitive data leakage.
func NewTailReaderWithBuffer(r io.Reader, size int, buffer []byte) *TailReader {
	if len(buffer) < size {
		panic("TailReader: buffer size must be at least the tail size")
	}
	return &TailReader{
		r:     r,
		buf:   make([]byte, 0, size),
		size:  size,
		queue: buffer,
	}
}

func (tr *TailReader) buffered() int {
	return tr.fillHead - tr.readHead - tr.size
}

// Undo the spliting between buf and queue
func (tr *TailReader) unsplit() {
	bufLen := len(tr.buf)
	if bufLen > 0 && tr.fillHead+bufLen < cap(tr.queue) {
		n := copy(tr.queue[tr.fillHead:], tr.buf)
		tr.fillHead += n
		tr.buf = tr.buf[0:]
	}
}

// Slide the buffer where readHeader become 0
func (tr *TailReader) slideBuffer() {
	if tr.readHead > 0 {
		copy(tr.queue, tr.queue[tr.readHead:tr.fillHead])
		tr.fillHead -= tr.readHead
		tr.readHead = 0
	}
}

func (tr *TailReader) Read(p []byte) (int, error) {
	// Slide the buffer
	tr.slideBuffer()
	tr.unsplit()
	// Bytes copied to buffer
	copied := 0
	outSize := len(p)
	queueCap := cap(tr.queue)
	// If there is stuffs to be written to and we also got stuffs to read (or inside local buffer)
	for copied < outSize && (!tr.readEOF || tr.buffered() > 0) {
		var n int
		if !tr.readEOF {
			n, err := tr.r.Read(tr.queue[tr.fillHead:])
			if n > 0 {
				tr.fillHead += n
			}
			if err == io.EOF {
				tr.readEOF = true
			} else if err != nil {
				return copied, err
			}
		}
		// Copy some bytes
		end := tr.fillHead - tr.size
		if tr.readHead < end {
			n = copy(p[copied:], tr.queue[tr.readHead:end])
			tr.readHead += n
			copied += n
		}
		if tr.fillHead == queueCap {
			tr.slideBuffer()
		}
	}
	if tr.buffered() <= 0 && copied == 0 {
		if tr.readEOF {
			// Steal some bytes for buffer
			if tr.fillHead >= tr.size {
				tr.buf = tr.buf[:tr.size]
				copy(tr.buf, tr.queue[tr.fillHead-tr.size:tr.fillHead])
				tr.fillHead -= tr.size
			} else {
				// If input is smaller than tail size, move all to tr.buf
				tr.buf = tr.buf[:tr.fillHead]
				copy(tr.buf, tr.queue[:tr.fillHead])
				tr.fillHead = 0
			}
			return 0, io.EOF
		}
		return 0, nil
	}
	// Steal some bytes for buffer
	if tr.fillHead >= tr.size {
		tr.buf = tr.buf[:tr.size]
		copy(tr.buf, tr.queue[tr.fillHead-tr.size:tr.fillHead])
		tr.fillHead -= tr.size
	} else if tr.readEOF {
		// If input is smaller than tail size, move all to tr.buf
		tr.buf = tr.buf[:tr.fillHead]
		copy(tr.buf, tr.queue[:tr.fillHead])
		tr.fillHead = 0
	}
	return copied, nil
}

// Tail returns the last N bytes after the stream is consumed.
func (tr *TailReader) Tail() ([]byte, error) {
	if !tr.readEOF {
		// force read underlying until EOF
		_, _ = io.Copy(io.Discard, tr)
	}
	// The caller should know that if the stream was shorter than size,
	// Tail will return fewer than size bytes.
	return append([]byte(nil), tr.buf...), nil
}
