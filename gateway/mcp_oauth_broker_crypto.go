package gateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	mcpOAuthBrokerSealDomain  = "tyk-mcp-oauth-broker-record-v1"
	mcpOAuthBrokerSealVersion = byte(1)
)

func (b *mcpOAuthBroker) brokerAEAD() (cipher.AEAD, error) {
	if b == nil || b.gw == nil {
		return nil, errors.New("OAuth broker encryption is not configured")
	}
	// Sealed records deliberately have no implicit previous-key fallback.
	// Rotating Secret invalidates outstanding broker grants and requires clients
	// to authorize again.
	secret := b.gw.GetConfig().Secret
	if secret == "" {
		return nil, errors.New("OAuth broker encryption secret is not configured")
	}
	key := sha256.Sum256([]byte(mcpOAuthBrokerSealDomain + "\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (b *mcpOAuthBroker) sealRecord(key string, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal OAuth broker record: %w", err)
	}
	aead, err := b.brokerAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate OAuth broker record nonce: %w", err)
	}
	sealed := make([]byte, 1, 1+len(nonce)+len(plain)+aead.Overhead())
	sealed[0] = mcpOAuthBrokerSealVersion
	sealed = append(sealed, nonce...)
	sealed = aead.Seal(sealed, nonce, plain, []byte(key))
	return sealed, nil
}

func (b *mcpOAuthBroker) openRecord(key string, sealed []byte, target any) error {
	aead, err := b.brokerAEAD()
	if err != nil {
		return err
	}
	if len(sealed) < 1+aead.NonceSize()+aead.Overhead() || sealed[0] != mcpOAuthBrokerSealVersion {
		return errors.New("invalid OAuth broker record")
	}
	nonce := sealed[1 : 1+aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, sealed[1+aead.NonceSize():], []byte(key))
	if err != nil {
		return errors.New("invalid OAuth broker record")
	}
	if err := json.Unmarshal(plain, target); err != nil {
		return errors.New("invalid OAuth broker record")
	}
	return nil
}

func (b *mcpOAuthBroker) putRecord(ctx context.Context, key string, value any, ttl time.Duration) error {
	sealed, err := b.sealRecord(key, value)
	if err != nil {
		return err
	}
	return b.store.Put(ctx, key, sealed, ttl)
}

func (b *mcpOAuthBroker) getRecord(ctx context.Context, key string, target any) (bool, error) {
	sealed, found, err := b.store.Get(ctx, key)
	if err != nil || !found {
		return found, err
	}
	if err := b.openRecord(key, sealed, target); err != nil {
		return false, err
	}
	return true, nil
}

func (b *mcpOAuthBroker) consumeRecord(ctx context.Context, key string, target any) (bool, error) {
	sealed, found, err := b.store.Consume(ctx, key)
	if err != nil || !found {
		return found, err
	}
	if err := b.openRecord(key, sealed, target); err != nil {
		return false, err
	}
	return true, nil
}
