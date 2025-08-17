package io

import (
	"io"
)

type RollingWriter struct {
	writer io.Writer
	buffer []byte
	size   int // Size of the buffer
}

// NewRollingWriter creates a new RollingWriter with the specified writer and buffer size.
func NewRollingWriter(writer io.Writer, bufferSize int) *RollingWriter {
	return &RollingWriter{
		writer: writer,
		buffer: make([]byte, 0, bufferSize),
		size:   bufferSize,
	}
}

// Write writes data to the RollingWriter.
// If the buffer exceeds the specified size, it writes the excess data to the underlying writer.
// It returns the number of bytes written and any error encountered.
func (rw *RollingWriter) Write(p []byte) (n int, err error) {
	if len(p) >= rw.size {
		// flush everything in buffer
		if len(rw.buffer) > 0 {
			if _, err := rw.writer.Write(rw.buffer); err != nil {
				return 0, err
			}
		}
		// directly write the excess of p, keep last size bytes
		excess := len(p) - rw.size
		if _, err := rw.writer.Write(p[:excess]); err != nil {
			return 0, err
		}
		rw.buffer = append(rw.buffer[:0], p[excess:]...)
		return len(p), nil
	}
	rw.buffer = append(rw.buffer, p...)
	if len(rw.buffer) >= rw.size {
		// Write the buffer to the underlying writer.
		excess := len(rw.buffer) - rw.size
		if _, err := rw.writer.Write(rw.buffer[:excess]); err != nil {
			return 0, err
		}
		// Keep only the last 'size' bytes in the buffer.
		rw.buffer = rw.buffer[excess:]
	}

	return len(p), nil
}

// Flush writes any remaining data in the buffer to the underlying writer.
// This effectively clears the buffer.
func (rw *RollingWriter) Flush() error {
	if len(rw.buffer) == 0 {
		return nil // Nothing to flush.
	}
	// Write the buffered data to the underlying writer.
	if _, err := rw.writer.Write(rw.buffer); err != nil {
		return err
	}
	rw.buffer = rw.buffer[:0] // Reset the buffer after flushing.
	return nil
}

// Range returns the current contents of the buffer specified by the start and end indices.
// It returns a slice of bytes containing the data from start to end.
func (rw *RollingWriter) Range(start, end int) []byte {
	if start < 0 {
		start = 0
	}
	if end > len(rw.buffer) {
		end = len(rw.buffer)
	}
	if start > end {
		return nil
	}
	// Return a copy of the current buffer.
	return append([]byte(nil), rw.buffer[start:end]...)
}

// Tail returns the last N bytes of the buffer.
// If N is greater than the current buffer size, it returns the entire buffer.
func (rw *RollingWriter) Tail(n int) []byte {
	if n <= 0 {
		return nil // No bytes to return.
	}
	if n > len(rw.buffer) {
		n = len(rw.buffer) // Adjust n to the current buffer size.
	}
	// Return the last N bytes of the buffer.
	return append([]byte(nil), rw.buffer[len(rw.buffer)-n:]...)
}

// Truncate truncates the buffer to the specified length.
// If the length is negative, it truncates to zero.
func (rw *RollingWriter) Truncate(length int) {
	if length < 0 {
		length = 0
	}
	if length > len(rw.buffer) {
		length = len(rw.buffer)
	}
	rw.buffer = rw.buffer[:length]
}

// Size returns the current size of the buffer.
func (rw *RollingWriter) Size() int {
	return len(rw.buffer)
}
