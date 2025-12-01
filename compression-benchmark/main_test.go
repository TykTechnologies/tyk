package main

import (
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
)

var testData []byte

func TestMain(m *testing.M) {
	var err error
	testData, err = os.ReadFile("testdata/sample-oas.json")
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// Snappy benchmarks

func BenchmarkSnappyCompress(b *testing.B) {
	b.SetBytes(int64(len(testData)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = snappy.Encode(nil, testData)
	}
}

func BenchmarkSnappyDecompress(b *testing.B) {
	compressed := snappy.Encode(nil, testData)
	b.SetBytes(int64(len(compressed)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = snappy.Decode(nil, compressed)
	}
}

// Zstd benchmarks

func BenchmarkZstdCompress(b *testing.B) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		b.Fatal(err)
	}
	defer encoder.Close()

	b.SetBytes(int64(len(testData)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = encoder.EncodeAll(testData, nil)
	}
}

func BenchmarkZstdDecompress(b *testing.B) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		b.Fatal(err)
	}
	compressed := encoder.EncodeAll(testData, nil)
	encoder.Close()

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		b.Fatal(err)
	}
	defer decoder.Close()

	b.SetBytes(int64(len(compressed)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = decoder.DecodeAll(compressed, nil)
	}
}

// Combined round-trip benchmarks (compress + decompress)

func BenchmarkSnappyRoundTrip(b *testing.B) {
	b.SetBytes(int64(len(testData)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		compressed := snappy.Encode(nil, testData)
		_, _ = snappy.Decode(nil, compressed)
	}
}

func BenchmarkZstdRoundTrip(b *testing.B) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		b.Fatal(err)
	}
	defer encoder.Close()

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		b.Fatal(err)
	}
	defer decoder.Close()

	b.SetBytes(int64(len(testData)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		compressed := encoder.EncodeAll(testData, nil)
		_, _ = decoder.DecodeAll(compressed, nil)
	}
}

// Compression ratio test (not a benchmark, but useful info)

func TestCompressionRatios(t *testing.T) {
	originalSize := len(testData)

	// Snappy
	snappyCompressed := snappy.Encode(nil, testData)
	snappySize := len(snappyCompressed)
	snappyRatio := float64(snappySize) / float64(originalSize) * 100

	// Zstd
	encoder, _ := zstd.NewWriter(nil)
	zstdCompressed := encoder.EncodeAll(testData, nil)
	encoder.Close()
	zstdSize := len(zstdCompressed)
	zstdRatio := float64(zstdSize) / float64(originalSize) * 100

	t.Logf("Original size: %d bytes", originalSize)
	t.Logf("Snappy: %d bytes (%.2f%%)", snappySize, snappyRatio)
	t.Logf("Zstd:   %d bytes (%.2f%%)", zstdSize, zstdRatio)
}
