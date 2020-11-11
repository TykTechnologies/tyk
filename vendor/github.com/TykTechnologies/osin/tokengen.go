package osin

import (
	"encoding/base64"

	"github.com/lonelycode/go-uuid/uuid"
)

// AuthorizeTokenGenDefault is the default authorization token generator
type AuthorizeTokenGenDefault struct {
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	token := uuid.NewRandom()
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}

// AccessTokenGenDefault is the default authorization token generator
type AccessTokenGenDefault struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenGenDefault) GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	token := uuid.NewRandom()
	accesstoken = base64.RawURLEncoding.EncodeToString([]byte(token))

	if generaterefresh {
		rtoken := uuid.NewRandom()
		refreshtoken = base64.RawURLEncoding.EncodeToString([]byte(rtoken))
	}
	return
}
