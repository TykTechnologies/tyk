package compression

import (
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

const maxDecompressedSize = 100 * 1024 * 1024

var (
	log = logrus.WithField("prefix", "compression")

	encoderPool = sync.Pool{
		New: func() interface{} {
			encoder, _ := zstd.NewWriter(nil)
			return encoder
		},
	}

	decoderPool = sync.Pool{
		New: func() interface{} {
			decoder, _ := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecompressedSize))
			return decoder
		},
	}
)

// CompressZstd compresses data using Zstd compression
// Returns the compressed data and logs compression statistics
func CompressZstd(data []byte) ([]byte, error) {
	encoder := encoderPool.Get().(*zstd.Encoder)
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
	decoder := decoderPool.Get().(*zstd.Decoder)
	defer decoderPool.Put(decoder)

	decompressed, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, err
	}

	log.WithField("decompressed_size", len(decompressed)).Debug("Data decompressed with Zstd")
	return decompressed, nil
}
