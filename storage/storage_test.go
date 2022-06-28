package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashAlgo(t *testing.T) {
	assert.Equal(t, "murmur32", HashAlgo(""))
	assert.Equal(t, "murmur32", HashAlgo("invalid"))
	assert.Equal(t, HashSha256, HashAlgo(HashSha256))
	assert.Equal(t, HashMurmur32, HashAlgo(HashMurmur32))
	assert.Equal(t, HashMurmur64, HashAlgo(HashMurmur64))
	assert.Equal(t, HashMurmur128, HashAlgo(HashMurmur128))
}
