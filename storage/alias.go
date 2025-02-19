package storage

import (
	"github.com/TykTechnologies/tyk/internal/crypto"
)

const (
	HashSha256    = crypto.HashSha256
	HashMurmur32  = crypto.HashMurmur32
	HashMurmur64  = crypto.HashMurmur64
	HashMurmur128 = crypto.HashMurmur128
)

var (
	HashStr = crypto.HashStr
	HashKey = crypto.HashKey
)

var (
	GenerateToken = crypto.GenerateToken
	TokenHashAlgo = crypto.TokenHashAlgo
	TokenID       = crypto.TokenID
	TokenOrg      = crypto.TokenOrg
)
