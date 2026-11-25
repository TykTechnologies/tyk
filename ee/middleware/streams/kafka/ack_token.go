package kafka

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const AckTokenVersion = 1

var (
	ErrInvalidAckToken = errors.New("invalid acknowledgement token")
	ErrExpiredAckToken = errors.New("acknowledgement token expired")
	ErrUnknownKeyID    = errors.New("unknown acknowledgement token key ID")
	ErrScopeMismatch   = errors.New("acknowledgement token scope mismatch")
)

// AckClaims identifies exactly one Kafka delivery. ExpiresAt is a Unix timestamp.
type AckClaims struct {
	Version       int    `json:"v"`
	KeyID         string `json:"kid"`
	Scope         string `json:"scope"`
	Epoch         uint64 `json:"epoch"`
	ReplayID      string `json:"replay,omitempty"`
	ClusterID     string `json:"cluster_id,omitempty"`
	Topic         string `json:"topic"`
	TopicID       string `json:"topic_id,omitempty"`
	Partition     int32  `json:"partition"`
	Offset        int64  `json:"offset"`
	ExpiresAt     int64  `json:"exp"`
	IssuedAt      int64  `json:"iat,omitempty"`
	ConsumerGroup string `json:"group,omitempty"`
	Owner         string `json:"owner,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
}

// AckTokenCodec signs and verifies compact, versioned HMAC-SHA256 tokens.
// Keeping verification keys by ID permits non-disruptive key rotation.
type AckTokenCodec struct {
	mu          sync.RWMutex
	activeKeyID string
	keys        map[string][]byte
	now         func() time.Time
	liveUntil   map[string]int64
}

func NewAckTokenCodec(activeKeyID string, keys map[string][]byte) (*AckTokenCodec, error) {
	if activeKeyID == "" || len(keys[activeKeyID]) == 0 {
		return nil, fmt.Errorf("%w: active key", ErrUnknownKeyID)
	}
	copyKeys := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" || strings.Contains(id, ".") || len(key) == 0 {
			return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, id)
		}
		copyKeys[id] = append([]byte(nil), key...)
	}
	return &AckTokenCodec{activeKeyID: activeKeyID, keys: copyKeys, now: time.Now, liveUntil: map[string]int64{}}, nil
}

func (c *AckTokenCodec) Sign(claims AckClaims) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	claims.Version = AckTokenVersion
	claims.KeyID = c.activeKeyID
	if err := validateAckClaims(claims); err != nil {
		return "", err
	}
	if claims.ExpiresAt > c.liveUntil[claims.KeyID] {
		c.liveUntil[claims.KeyID] = claims.ExpiresAt
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signed := fmt.Sprintf("v%d.%s.%s", AckTokenVersion, claims.KeyID, encoded)
	mac := hmac.New(sha256.New, c.keys[claims.KeyID])
	_, _ = mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify validates format, signature, expiry, and optionally the expected scope.
func (c *AckTokenCodec) Verify(token, expectedScope string) (AckClaims, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var claims AckClaims
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] == "" {
		return claims, ErrInvalidAckToken
	}
	key, ok := c.keys[parts[1]]
	if !ok {
		return claims, ErrUnknownKeyID
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return claims, ErrInvalidAckToken
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strings.Join(parts[:3], ".")))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return claims, ErrInvalidAckToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return AckClaims{}, ErrInvalidAckToken
	}
	if claims.Version != AckTokenVersion || claims.KeyID != parts[1] {
		return AckClaims{}, ErrInvalidAckToken
	}
	if err := validateAckClaims(claims); err != nil {
		return AckClaims{}, err
	}
	if expectedScope != "" && claims.Scope != expectedScope {
		return AckClaims{}, ErrScopeMismatch
	}
	if !c.now().Before(time.Unix(claims.ExpiresAt, 0)) {
		return AckClaims{}, ErrExpiredAckToken
	}
	return claims, nil
}

func (c *AckTokenCodec) replaceKeyring(active string, keys map[string][]byte, force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	if !force {
		for id, expiry := range c.liveUntil {
			if _, retained := keys[id]; !retained && expiry > now {
				return fmt.Errorf("%w: key %q has live tokens until %d", ErrInvalidAckSigningKeys, id, expiry)
			}
		}
	}
	c.activeKeyID, c.keys = active, keys
	for id := range c.liveUntil {
		if _, retained := keys[id]; !retained {
			delete(c.liveUntil, id)
		}
	}
	return nil
}

func (c *AckTokenCodec) canReplace(keys map[string][]byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now().Unix()
	for id, expiry := range c.liveUntil {
		replacement, retained := keys[id]
		if expiry > now && (!retained || !hmac.Equal(replacement, c.keys[id])) {
			return fmt.Errorf("%w: key %q has live tokens until %d", ErrInvalidAckSigningKeys, id, expiry)
		}
	}
	return nil
}

func validateAckClaims(c AckClaims) error {
	if c.Scope == "" || c.Topic == "" || c.Partition < 0 || c.Offset < 0 || c.ExpiresAt <= 0 {
		return ErrInvalidAckToken
	}
	if c.ConsumerGroup != "" || c.Owner != "" || c.Nonce != "" || c.IssuedAt != 0 {
		if c.ConsumerGroup == "" || c.Owner == "" || c.Nonce == "" || c.IssuedAt <= 0 || c.IssuedAt > c.ExpiresAt {
			return ErrInvalidAckToken
		}
	}
	return nil
}

// EventIdentity is stable across redeliveries of the same scoped Kafka record.
// ClusterID and topicIncarnation prevent collisions after a topic is recreated
// or when one stream consumes identically named topics from multiple clusters.
func EventIdentity(scope, clusterID, topic, topicIncarnation string, partition int32, offset int64) string {
	return hashIdentity("event", scope, clusterID, topic, topicIncarnation, fmt.Sprint(partition), fmt.Sprint(offset))
}

// DeliveryIdentity is stable for a delivery epoch/replay, but changes on either.
func DeliveryIdentity(eventID string, epoch uint64, replayID string) string {
	return hashIdentity("delivery", eventID, fmt.Sprint(epoch), replayID)
}

func hashIdentity(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}
