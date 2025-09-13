package io_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	_io "github.com/ngeojiajun/go-filecrypt/internal/io"
	"github.com/ngeojiajun/go-filecrypt/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestCorrectNess(t *testing.T) {
	testPayload, err := utils.GenerateRandomBytes(60 * 4096) // 60 pages
	assert.NoError(t, err, "cannot generate random bytes for testing")
	reader := bytes.NewReader(testPayload)
	tailReader := _io.NewTailReader(reader, 64)
	tmp := make([]byte, 1028) // 0.5 pages
	idx := 0
	round := 0
	for err == nil {
		round += 1
		t.Logf("Round %d", round)
		var n int
		n, err = tailReader.Read(tmp)
		if n > 0 {
			assert.Equal(t, testPayload[idx:idx+n], tmp[:n])
			idx += n
		}
	}
	assert.ErrorIs(t, err, io.EOF)
	tail, err := tailReader.Tail()
	assert.NoError(t, err, "cannot read tail")
	assert.Equal(t, testPayload[idx:], tail)
}

func BenchmarkTailReader(rootB *testing.B) {
	pages := []int{60, 600, 6000}
	for _, p := range pages {
		testPayload, err := utils.GenerateRandomBytes(p * 4096)
		assert.NoError(rootB, err, "cannot generate random bytes for testing")
		bufSizes := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192}
		for _, size := range bufSizes {
			rootB.Run(fmt.Sprintf("%d-pages(%dKB)-%dKB-buffer", p, p*4, size), func(b *testing.B) {
				tmp := make([]byte, size*1024)
				reader := bytes.NewReader(testPayload)
				processedBytes := int64(0)
				b.ResetTimer()
				for b.Loop() {
					var err error
					b.StopTimer()
					reader.Reset(testPayload)
					tailReader := _io.NewTailReader(reader, 64)
					b.StartTimer()
					for err == nil {
						var n int
						n, err = tailReader.Read(tmp)
						processedBytes += int64(n)
					}
				}
				b.ReportMetric(float64(processedBytes)/float64(1024*1024), "MB/s")
			})
		}
	}
}
