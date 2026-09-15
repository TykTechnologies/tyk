package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSharedAckSigningKeysCrossInstanceAndRotation(t *testing.T) {
	oldSecret := []byte("old-cluster-secret-with-at-least-32-bytes")
	newSecret := []byte("new-cluster-secret-with-at-least-32-bytes")
	scope := "api\x00employees\x00input-0"
	now := time.Unix(1_800_000_000, 0)

	first, err := NewSharedAckSigningKeyProvider("2026-01", map[string][]byte{"2026-01": oldSecret})
	require.NoError(t, err)
	firstCodec, err := first.ResolveAckTokenCodec(context.Background(), scope)
	require.NoError(t, err)
	firstCodec.now = func() time.Time { return now }
	token, err := firstCodec.Sign(AckClaims{Scope: scope, Epoch: 2, Topic: "employees", Offset: 4, ExpiresAt: now.Add(time.Hour).Unix()})
	require.NoError(t, err)

	// A distinct gateway with the same shared secret derives the same key.
	second, err := NewSharedAckSigningKeyProvider("2026-01", map[string][]byte{"2026-01": append([]byte(nil), oldSecret...)})
	require.NoError(t, err)
	secondCodec, err := second.ResolveAckTokenCodec(context.Background(), scope)
	require.NoError(t, err)
	secondCodec.now = func() time.Time { return now }
	_, err = secondCodec.Verify(token, scope)
	require.NoError(t, err)

	// The rotated active key signs new tokens while the overlap key verifies old ones.
	require.NoError(t, second.Rotate("2026-02", map[string][]byte{"2026-01": oldSecret, "2026-02": newSecret}))
	overlapCodec, err := second.ResolveAckTokenCodec(context.Background(), scope)
	require.NoError(t, err)
	overlapCodec.now = func() time.Time { return now }
	_, err = overlapCodec.Verify(token, scope)
	require.NoError(t, err)
	newToken, err := overlapCodec.Sign(AckClaims{Scope: scope, Epoch: 2, Topic: "employees", Offset: 5, ExpiresAt: now.Add(time.Hour).Unix()})
	require.NoError(t, err)
	require.Contains(t, newToken, "v1.2026-02.")

	// Once overlap ends, the old key ID is rejected rather than tried against
	// another secret.
	require.NoError(t, second.Rotate("2026-02", map[string][]byte{"2026-02": newSecret}))
	removedCodec, err := second.ResolveAckTokenCodec(context.Background(), scope)
	require.NoError(t, err)
	removedCodec.now = func() time.Time { return now }
	_, err = removedCodec.Verify(token, scope)
	require.ErrorIs(t, err, ErrUnknownKeyID)
	_, err = removedCodec.Verify(newToken, scope)
	require.NoError(t, err)
}

func TestSharedAckSigningKeysDomainSeparation(t *testing.T) {
	secret := []byte("one-cluster-secret-with-at-least-32-bytes")
	provider, err := NewSharedAckSigningKeyProvider("key", map[string][]byte{"key": secret})
	require.NoError(t, err)
	one, err := provider.ResolveAckTokenCodec(context.Background(), "api-a")
	require.NoError(t, err)
	two, err := provider.ResolveAckTokenCodec(context.Background(), "api-b")
	require.NoError(t, err)
	now := time.Now()
	one.now, two.now = func() time.Time { return now }, func() time.Time { return now }
	token, err := one.Sign(AckClaims{Scope: "api-a", Topic: "employees", ExpiresAt: now.Add(time.Hour).Unix()})
	require.NoError(t, err)
	_, err = two.Verify(token, "api-a")
	require.ErrorIs(t, err, ErrInvalidAckToken)

	// Derivation is framed, so concatenation cannot create the same key input.
	require.NotEqual(t, deriveAckSigningKey(secret, "ab", "c"), deriveAckSigningKey(secret, "a", "bc"))
}

func TestSharedAckSigningKeysValidationAndIsolation(t *testing.T) {
	_, err := NewSharedAckSigningKeyProvider("missing", map[string][]byte{"key": make([]byte, 32)})
	require.ErrorIs(t, err, ErrInvalidAckSigningKeys)
	_, err = NewSharedAckSigningKeyProvider("bad.id", map[string][]byte{"bad.id": make([]byte, 32)})
	require.ErrorIs(t, err, ErrInvalidAckSigningKeys)
	_, err = NewSharedAckSigningKeyProvider("short", map[string][]byte{"short": []byte("short")})
	require.ErrorIs(t, err, ErrInvalidAckSigningKeys)

	provider, err := NewSharedAckSigningKeyProvider("key", map[string][]byte{"key": make([]byte, 32)})
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = provider.ResolveAckTokenCodec(canceled, "scope")
	require.True(t, errors.Is(err, context.Canceled))
	_, err = provider.ResolveAckTokenCodec(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidAckSigningKeys)
}

func TestSharedAckSigningKeyProviderRotatesLiveCodecAndProtectsRemoval(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	oldSecret, newSecret := []byte("old-shared-secret-at-least-32-bytes-long"), []byte("new-shared-secret-at-least-32-bytes-long")
	provider, err := NewSharedAckSigningKeyProvider("old", map[string][]byte{"old": oldSecret})
	require.NoError(t, err)
	codec, err := provider.ResolveAckTokenCodec(context.Background(), "scope")
	require.NoError(t, err)
	codec.now = func() time.Time { return now }
	oldToken, err := codec.Sign(AckClaims{Scope: "scope", Topic: "topic", Offset: 1, ExpiresAt: now.Add(time.Hour).Unix()})
	require.NoError(t, err)
	require.NoError(t, provider.Rotate("new", map[string][]byte{"old": oldSecret, "new": newSecret}))
	_, err = codec.Verify(oldToken, "scope")
	require.NoError(t, err)
	newToken, err := codec.Sign(AckClaims{Scope: "scope", Topic: "topic", Offset: 2, ExpiresAt: now.Add(time.Hour).Unix()})
	require.NoError(t, err)
	require.Contains(t, newToken, ".new.")
	require.Error(t, provider.Rotate("new", map[string][]byte{"new": newSecret}))
	require.NoError(t, provider.ForceRotate("new", map[string][]byte{"new": newSecret}))
	_, err = codec.Verify(oldToken, "scope")
	require.ErrorIs(t, err, ErrUnknownKeyID)
}
