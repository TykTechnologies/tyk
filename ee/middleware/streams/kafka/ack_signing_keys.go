package kafka

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	ackSigningKeyDomain = "tyk.streams.kafka.external-ack.signing-key.v1"
	minAckRootSecretLen = 32
)

var ErrInvalidAckSigningKeys = errors.New("invalid acknowledgement signing keys")

// AckTokenCodecResolver supplies a scope-specific token codec. Implementations
// must return equivalent codecs on every gateway that serves the same stream.
type AckTokenCodecResolver interface {
	ResolveAckTokenCodec(context.Context, string) (*AckTokenCodec, error)
}

// SharedAckSigningKeyProvider derives scope-specific signing keys from shared
// root secrets. A rotation snapshot contains the active key and any verification
// keys retained for overlap with tokens issued before rotation.
type SharedAckSigningKeyProvider struct {
	mu       sync.RWMutex
	activeID string
	secrets  map[string][]byte
	codecs   map[string]*AckTokenCodec
}

func NewSharedAckSigningKeyProvider(activeID string, secrets map[string][]byte) (*SharedAckSigningKeyProvider, error) {
	p := &SharedAckSigningKeyProvider{codecs: map[string]*AckTokenCodec{}}
	if err := p.Rotate(activeID, secrets); err != nil {
		return nil, err
	}
	return p, nil
}

// Rotate atomically replaces the active and overlap key set. Removing an old
// key immediately causes tokens bearing that key ID to be rejected.
func (p *SharedAckSigningKeyProvider) Rotate(activeID string, secrets map[string][]byte) error {
	return p.rotate(activeID, secrets, false)
}

// ForceRotate explicitly invalidates outstanding capabilities signed by a
// removed key. Operators must use this only together with delivery invalidation.
func (p *SharedAckSigningKeyProvider) ForceRotate(activeID string, secrets map[string][]byte) error {
	return p.rotate(activeID, secrets, true)
}

func (p *SharedAckSigningKeyProvider) rotate(activeID string, secrets map[string][]byte, force bool) error {
	if p == nil {
		return fmt.Errorf("%w: nil provider", ErrInvalidAckSigningKeys)
	}
	validated, err := validateAndCopyAckSecrets(activeID, secrets)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if !force {
		for scope, codec := range p.codecs {
			keys := make(map[string][]byte, len(validated))
			for id, secret := range validated {
				keys[id] = deriveAckSigningKey(secret, id, scope)
			}
			if err := codec.canReplace(keys); err != nil {
				p.mu.Unlock()
				return err
			}
		}
	}
	for scope, codec := range p.codecs {
		keys := make(map[string][]byte, len(validated))
		for id, secret := range validated {
			keys[id] = deriveAckSigningKey(secret, id, scope)
		}
		if err := codec.replaceKeyring(activeID, keys, true); err != nil {
			p.mu.Unlock()
			return err
		}
	}
	p.activeID = activeID
	p.secrets = validated
	p.mu.Unlock()
	return nil
}

func (p *SharedAckSigningKeyProvider) ResolveAckTokenCodec(ctx context.Context, scope string) (*AckTokenCodec, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil provider", ErrInvalidAckSigningKeys)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scope == "" {
		return nil, fmt.Errorf("%w: empty scope", ErrInvalidAckSigningKeys)
	}

	p.mu.RLock()
	if codec := p.codecs[scope]; codec != nil {
		p.mu.RUnlock()
		return codec, nil
	}
	activeID := p.activeID
	secrets := make(map[string][]byte, len(p.secrets))
	for id, secret := range p.secrets {
		secrets[id] = append([]byte(nil), secret...)
	}
	p.mu.RUnlock()

	keys := make(map[string][]byte, len(secrets))
	for id, secret := range secrets {
		keys[id] = deriveAckSigningKey(secret, id, scope)
	}
	codec, err := NewAckTokenCodec(activeID, keys)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if existing := p.codecs[scope]; existing != nil {
		codec = existing
	} else {
		p.codecs[scope] = codec
	}
	p.mu.Unlock()
	return codec, nil
}

func (p *SharedAckSigningKeyProvider) snapshot() (string, map[string][]byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copySecrets := make(map[string][]byte, len(p.secrets))
	for id, secret := range p.secrets {
		copySecrets[id] = append([]byte(nil), secret...)
	}
	return p.activeID, copySecrets
}

func validateAndCopyAckSecrets(activeID string, secrets map[string][]byte) (map[string][]byte, error) {
	if activeID == "" || len(secrets) == 0 {
		return nil, fmt.Errorf("%w: active key and secrets are required", ErrInvalidAckSigningKeys)
	}
	copySecrets := make(map[string][]byte, len(secrets))
	for id, secret := range secrets {
		if id == "" || len(secret) < minAckRootSecretLen {
			return nil, fmt.Errorf("%w: key %q must have at least %d bytes", ErrInvalidAckSigningKeys, id, minAckRootSecretLen)
		}
		copySecrets[id] = append([]byte(nil), secret...)
	}
	if _, ok := copySecrets[activeID]; !ok {
		return nil, fmt.Errorf("%w: active key %q is missing", ErrInvalidAckSigningKeys, activeID)
	}
	// Reuse the codec's key-ID validation so provider and token formats cannot
	// drift apart.
	if _, err := NewAckTokenCodec(activeID, copySecrets); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAckSigningKeys, err)
	}
	return copySecrets, nil
}

func deriveAckSigningKey(root []byte, keyID, scope string) []byte {
	mac := hmac.New(sha256.New, root)
	writeFramedAckKeyPart(mac, ackSigningKeyDomain)
	writeFramedAckKeyPart(mac, keyID)
	writeFramedAckKeyPart(mac, scope)
	return mac.Sum(nil)
}

type ackKeyHashWriter interface {
	Write([]byte) (int, error)
}

func writeFramedAckKeyPart(w ackKeyHashWriter, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write([]byte(value))
}
