package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

type compressor interface {
	compress(data []byte) ([]byte, error)
	decompress(data []byte) ([]byte, error)
	name() string
}

// LZ4 compressor
type lz4Compressor struct{}

func (c *lz4Compressor) name() string { return "LZ4" }

func (c *lz4Compressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *lz4Compressor) decompress(data []byte) ([]byte, error) {
	r := lz4.NewReader(bytes.NewReader(data))
	return io.ReadAll(r)
}

// Gzip compressor
type gzipCompressor struct{}

func (c *gzipCompressor) name() string { return "Gzip" }

func (c *gzipCompressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *gzipCompressor) decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// Zlib compressor
type zlibCompressor struct{}

func (c *zlibCompressor) name() string { return "Zlib" }

func (c *zlibCompressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *zlibCompressor) decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// Zstd compressor
type zstdCompressor struct{}

func (c *zstdCompressor) name() string { return "Zstd" }

func (c *zstdCompressor) compress(data []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	return encoder.EncodeAll(data, nil), nil
}

func (c *zstdCompressor) decompress(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	return decoder.DecodeAll(data, nil)
}

// Snappy compressor
type snappyCompressor struct{}

func (c *snappyCompressor) name() string { return "Snappy" }

func (c *snappyCompressor) compress(data []byte) ([]byte, error) {
	return snappy.Encode(nil, data), nil
}

func (c *snappyCompressor) decompress(data []byte) ([]byte, error) {
	return snappy.Decode(nil, data)
}

func getCompressor(algorithm string) compressor {
	switch algorithm {
	case "lz4":
		return &lz4Compressor{}
	case "gzip":
		return &gzipCompressor{}
	case "zlib":
		return &zlibCompressor{}
	case "zstd":
		return &zstdCompressor{}
	case "snappy":
		return &snappyCompressor{}
	default:
		return nil
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <algorithm> <path-to-json>")
		fmt.Println("Algorithms: lz4, gzip, zlib, zstd, snappy")
		os.Exit(1)
	}

	algorithm := os.Args[1]
	path := os.Args[2]

	comp := getCompressor(algorithm)
	if comp == nil {
		fmt.Printf("Unknown algorithm: %s\n", algorithm)
		fmt.Println("Supported algorithms: lz4, gzip, zlib, zstd")
		os.Exit(1)
	}

	// Load JSON from disk
	start := time.Now()
	jsonBytes, err := os.ReadFile(path)
	must(err)
	loadTime := time.Since(start)

	originalSize := len(jsonBytes)

	// --- Compression ---
	start = time.Now()
	compressed, err := comp.compress(jsonBytes)
	must(err)
	compressTime := time.Since(start)

	compressedSize := len(compressed)

	// --- Decompression ---
	start = time.Now()
	decompressed, err := comp.decompress(compressed)
	must(err)
	decompressTime := time.Since(start)

	// Sanity check
	if !bytes.Equal(decompressed, jsonBytes) {
		panic("decompressed bytes do not match original")
	}

	// --- Results ---
	fmt.Printf("======= %s Benchmark =======\n", comp.name())
	fmt.Printf("Input file:     %s\n", path)
	fmt.Printf("Original size:  %d bytes\n", originalSize)
	fmt.Printf("%s size:      %d bytes\n", comp.name(), compressedSize)
	fmt.Printf("Ratio:          %.2f%%\n", float64(compressedSize)/float64(originalSize)*100)
	fmt.Printf("Compression saved: %.2f%%\n", 100-(float64(compressedSize)/float64(originalSize)*100))

	fmt.Printf("\nFile load time:       %s\n", loadTime)
	fmt.Printf("Compress time:   %s\n", compressTime)
	fmt.Printf("Decompress time: %s\n", decompressTime)
}
