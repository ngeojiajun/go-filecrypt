package io_test

import (
	"bytes"
	"io"
	"testing"

	_io "github.com/ngeojiajun/go-filecrypt/internal/io"
	"github.com/stretchr/testify/assert"
)

func TestTailReaderShortInput(t *testing.T) {
	testPayload := []byte("short") // 5 bytes
	tailSize := 10
	reader := bytes.NewReader(testPayload)
	tailReader := _io.NewTailReader(reader, tailSize)

	tmp := make([]byte, 10)
	n, err := tailReader.Read(tmp)

	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, io.EOF)

	tail, err := tailReader.Tail()
	assert.NoError(t, err)
	assert.Equal(t, testPayload, tail)
}
