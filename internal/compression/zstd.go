package compression

import (
	"bytes"
	"errors"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

const maxDecompressedSize = 100 * 1024 * 1024

var (
	log = logrus.WithField("prefix", "compression")

	// zstdMagicBytes are the magic bytes that identify a Zstd frame
	// See: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#zstandard-frames
	zstdMagicBytes = []byte{0x28, 0xB5, 0x2F, 0xFD}

	encoderPool = sync.Pool{
		New: func() interface{} {
			encoder, err := zstd.NewWriter(nil)
			if err != nil {
				log.WithError(err).Error("Failed to create Zstd encoder")
				return nil
			}
			return encoder
		},
	}

	decoderPool = sync.Pool{
		New: func() interface{} {
			decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecompressedSize))
			if err != nil {
				log.WithError(err).Error("Failed to create Zstd decoder")
				return nil
			}
			return decoder
		},
	}
)

// CompressZstd compresses data using Zstd compression
// Returns the compressed data and an error if compression fails
func CompressZstd(data []byte) ([]byte, error) {
	encoderInterface := encoderPool.Get()
	if encoderInterface == nil {
		return nil, errors.New("failed to get Zstd encoder from pool")
	}

	encoder, ok := encoderInterface.(*zstd.Encoder)
	if !ok {
		return nil, errors.New("invalid encoder type in pool")
	}
	defer encoderPool.Put(encoder)

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
	decoderInterface := decoderPool.Get()
	if decoderInterface == nil {
		return nil, errors.New("failed to get Zstd decoder from pool")
	}

	decoder, ok := decoderInterface.(*zstd.Decoder)
	if !ok {
		return nil, errors.New("invalid decoder type in pool")
	}
	defer decoderPool.Put(decoder)

	decompressed, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, err
	}

	log.WithField("decompressed_size", len(decompressed)).Debug("Data decompressed with Zstd")
	return decompressed, nil
}

// IsZstdCompressed checks if the data starts with Zstd magic bytes
func IsZstdCompressed(data []byte) bool {
	return len(data) >= 4 && bytes.Equal(data[:4], zstdMagicBytes)
}
