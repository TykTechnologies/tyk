package kafka

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAckTokenCodec(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	codec, err := NewAckTokenCodec("current", map[string][]byte{"old": []byte("old secret"), "current": []byte("current secret")})
	require.NoError(t, err)
	codec.now = func() time.Time { return now }
	claims := AckClaims{Scope: "api/stream", Epoch: 7, ReplayID: "replay-2", Topic: "employees", Partition: 3, Offset: 42, ExpiresAt: now.Add(time.Minute).Unix()}
	token, err := codec.Sign(claims)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(token, "v1.current."))
	decoded, err := codec.Verify(token, claims.Scope)
	require.NoError(t, err)
	require.Equal(t, AckTokenVersion, decoded.Version)
	require.Equal(t, "current", decoded.KeyID)
	require.Equal(t, claims.Scope, decoded.Scope)
	require.Equal(t, claims.Epoch, decoded.Epoch)
	require.Equal(t, claims.ReplayID, decoded.ReplayID)
	require.Equal(t, claims.Topic, decoded.Topic)
	require.Equal(t, claims.Partition, decoded.Partition)
	require.Equal(t, claims.Offset, decoded.Offset)

	t.Run("tamper", func(t *testing.T) {
		parts := strings.Split(token, ".")
		parts[2] = "e30"
		_, err := codec.Verify(strings.Join(parts, "."), claims.Scope)
		require.ErrorIs(t, err, ErrInvalidAckToken)
	})
	t.Run("scope", func(t *testing.T) {
		_, err := codec.Verify(token, "another/stream")
		require.ErrorIs(t, err, ErrScopeMismatch)
	})
	t.Run("expired including exact boundary", func(t *testing.T) {
		codec.now = func() time.Time { return time.Unix(claims.ExpiresAt, 0) }
		_, err := codec.Verify(token, claims.Scope)
		require.ErrorIs(t, err, ErrExpiredAckToken)
	})
	t.Run("unknown key ID", func(t *testing.T) {
		parts := strings.Split(token, ".")
		parts[1] = "removed"
		_, err := codec.Verify(strings.Join(parts, "."), claims.Scope)
		require.ErrorIs(t, err, ErrUnknownKeyID)
	})
}

func TestAckTokenCodecRotationAndValidation(t *testing.T) {
	_, err := NewAckTokenCodec("missing", map[string][]byte{"key": []byte("secret")})
	require.ErrorIs(t, err, ErrUnknownKeyID)
	_, err = NewAckTokenCodec("bad.id", map[string][]byte{"bad.id": []byte("secret")})
	require.ErrorIs(t, err, ErrUnknownKeyID)
	old, err := NewAckTokenCodec("old", map[string][]byte{"old": []byte("old"), "new": []byte("new")})
	require.NoError(t, err)
	now := time.Now()
	old.now = func() time.Time { return now }
	token, err := old.Sign(AckClaims{Scope: "s", Topic: "t", ExpiresAt: now.Add(time.Hour).Unix()})
	require.NoError(t, err)
	rotated, err := NewAckTokenCodec("new", map[string][]byte{"old": []byte("old"), "new": []byte("new")})
	require.NoError(t, err)
	rotated.now = func() time.Time { return now }
	_, err = rotated.Verify(token, "s")
	require.NoError(t, err)

	invalid := []AckClaims{
		{Topic: "t", ExpiresAt: 1},
		{Scope: "s", ExpiresAt: 1},
		{Scope: "s", Topic: "t", Partition: -1, ExpiresAt: 1},
		{Scope: "s", Topic: "t", Offset: -1, ExpiresAt: 1},
		{Scope: "s", Topic: "t"},
	}
	for _, claims := range invalid {
		_, err := rotated.Sign(claims)
		require.True(t, errors.Is(err, ErrInvalidAckToken))
	}
}

func TestStableIdentities(t *testing.T) {
	event := EventIdentity("scope", "cluster", "topic", "incarnation", 1, 2)
	require.Equal(t, event, EventIdentity("scope", "cluster", "topic", "incarnation", 1, 2))
	require.NotEqual(t, event, EventIdentity("scope", "cluster", "topic", "incarnation", 1, 3))
	require.NotEqual(t, event, EventIdentity("scope", "other-cluster", "topic", "incarnation", 1, 2))
	require.NotEqual(t, event, EventIdentity("scope", "cluster", "topic", "new-incarnation", 1, 2))
	delivery := DeliveryIdentity(event, 4, "r")
	require.Equal(t, delivery, DeliveryIdentity(event, 4, "r"))
	require.NotEqual(t, delivery, DeliveryIdentity(event, 5, "r"))
	require.NotEqual(t, delivery, DeliveryIdentity(event, 4, "other"))
	// Length framing prevents ambiguous concatenation.
	require.NotEqual(t, EventIdentity("a", "b", "c", "d", 1, 2), EventIdentity("ab", "b", "c", "d", 1, 2))
}
