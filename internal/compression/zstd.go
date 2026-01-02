package compression

import (
	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("prefix", "compression")

// CompressZstd compresses data using Zstd compression
// Returns the compressed data and logs compression statistics
func CompressZstd(data []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()

	compressed := encoder.EncodeAll(data, make([]byte, 0, len(data)))

	var compressionRatio float64
	if len(data) > 0 {
		compressionRatio = float64(len(data)-len(compressed)) / float64(len(data)) * 100
	}
	log.WithFields(logrus.Fields{
		"original_size":     len(data),
		"compressed_size":   len(compressed),
		"compression_ratio": compressionRatio,
	}).Debug("Data compressed with Zstd")

	return compressed, nil
}

// DecompressZstd decompresses Zstd-compressed data
func DecompressZstd(data []byte) ([]byte, error) {
	const maxDecompressedSize = 100 * 1024 * 1024 // 100MB

	decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecompressedSize))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	decompressed, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, err
	}

	log.WithField("decompressed_size", len(decompressed)).Debug("Data decompressed with Zstd")
	return decompressed, nil
}
