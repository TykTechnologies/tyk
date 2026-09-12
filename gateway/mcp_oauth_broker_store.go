package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/storage"
)

var (
	errMCPOAuthBrokerStoreCollision = errors.New("MCP OAuth broker key already exists")
	errMCPOAuthBrokerFamilyRevoked  = errors.New("MCP OAuth broker token family is revoked")
	errMCPOAuthBrokerClientLimit    = errors.New("MCP OAuth broker client registration limit reached")
)

type mcpOAuthBrokerIssueRecord struct {
	key   string
	value []byte
	ttl   time.Duration
}

// mcpOAuthBrokerStore is deliberately smaller than storage.Handler. OAuth
// transaction values must support a real atomic consume operation so callback,
// code, and refresh replay cannot win on different Gateway instances.
type mcpOAuthBrokerStore interface {
	Put(context.Context, string, []byte, time.Duration) error
	Get(context.Context, string) ([]byte, bool, error)
	Consume(context.Context, string) ([]byte, bool, error)
	Issue(context.Context, string, []mcpOAuthBrokerIssueRecord) error
	RegisterClient(context.Context, string, string, string, []byte, time.Duration, int64) error
	ClaimClient(context.Context, string, string) ([]byte, bool, error)
	RestoreClient(context.Context, string, string) error
	ReplaceClaimedClient(context.Context, string, string, string, string, []byte, time.Duration) error
	FinishClientDeletion(context.Context, string, string, string, string) error
}

type redisMCPOAuthBrokerStore struct {
	cluster *storage.RedisCluster
}

func newRedisMCPOAuthBrokerStore(gw *Gateway) *redisMCPOAuthBrokerStore {
	return &redisMCPOAuthBrokerStore{cluster: &storage.RedisCluster{
		KeyPrefix: "mcp-oauth-broker:", ConnectionHandler: gw.StorageConnectionHandler,
	}}
}

func (s *redisMCPOAuthBrokerStore) client() (redis.UniversalClient, error) {
	if s == nil || s.cluster == nil {
		return nil, errors.New("MCP OAuth broker store is not configured")
	}
	return s.cluster.Client()
}

func (s *redisMCPOAuthBrokerStore) key(key string) string {
	return s.cluster.KeyPrefix + key
}

func (s *redisMCPOAuthBrokerStore) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	created, err := client.SetNX(ctx, s.key(key), value, ttl).Result()
	if err != nil {
		return err
	}
	if !created {
		return errMCPOAuthBrokerStoreCollision
	}
	return nil
}

func (s *redisMCPOAuthBrokerStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	client, err := s.client()
	if err != nil {
		return nil, false, err
	}
	value, err := client.Get(ctx, s.key(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

var consumeMCPOAuthBrokerValue = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value then
  return nil
end
redis.call("DEL", KEYS[1])
return value
`)

func (s *redisMCPOAuthBrokerStore) Consume(ctx context.Context, key string) ([]byte, bool, error) {
	client, err := s.client()
	if err != nil {
		return nil, false, err
	}
	value, err := consumeMCPOAuthBrokerValue.Run(ctx, client, []string{s.key(key)}).Text()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("atomically consume OAuth broker value: %w", err)
	}
	return []byte(value), true, nil
}

var issueMCPOAuthBrokerFamily = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 then
  return 0
end
for index = 2, #KEYS do
  if redis.call("EXISTS", KEYS[index]) == 1 then
    return -1
  end
end
for index = 2, #KEYS do
  local argument = ((index - 2) * 2) + 1
  redis.call("SET", KEYS[index], ARGV[argument], "PX", ARGV[argument + 1])
end
return 1
`)

func (s *redisMCPOAuthBrokerStore) Issue(ctx context.Context, revokedKey string, records []mcpOAuthBrokerIssueRecord) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("MCP OAuth broker issue transaction has no records")
	}
	keys := make([]string, 1, len(records)+1)
	keys[0] = s.key(revokedKey)
	arguments := make([]any, 0, len(records)*2)
	for _, record := range records {
		if record.key == "" || len(record.value) == 0 || record.ttl <= 0 {
			return errors.New("MCP OAuth broker issue transaction has an invalid record")
		}
		keys = append(keys, s.key(record.key))
		arguments = append(arguments, record.value, record.ttl.Milliseconds())
	}
	result, err := issueMCPOAuthBrokerFamily.Run(ctx, client, keys, arguments...).Int64()
	if err != nil {
		return fmt.Errorf("atomically issue OAuth broker token family: %w", err)
	}
	switch result {
	case 1:
		return nil
	case 0:
		return errMCPOAuthBrokerFamilyRevoked
	case -1:
		return errMCPOAuthBrokerStoreCollision
	default:
		return fmt.Errorf("atomically issue OAuth broker token family: unexpected result %d", result)
	}
}

var registerMCPOAuthBrokerClient = redis.NewScript(`
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", ARGV[1])
if redis.call("EXISTS", KEYS[2]) == 1 then
  return -1
end
if redis.call("ZCARD", KEYS[1]) >= tonumber(ARGV[2]) then
  return 0
end
redis.call("SET", KEYS[2], ARGV[4], "PX", ARGV[3])
redis.call("ZADD", KEYS[1], ARGV[5], ARGV[6])
redis.call("PEXPIRE", KEYS[1], ARGV[3])
return 1
`)

// RegisterClient atomically applies the per-API registration limit and stores
// the sealed client mapping. The sorted-set index contains only opaque client
// key hashes and is pruned by expiry on every registration attempt.
func (s *redisMCPOAuthBrokerStore) RegisterClient(ctx context.Context, indexKey, clientKey, member string, value []byte, ttl time.Duration, limit int64) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	if indexKey == "" || clientKey == "" || member == "" || len(value) == 0 || ttl <= 0 || limit <= 0 {
		return errors.New("MCP OAuth broker client registration has invalid storage parameters")
	}
	now := time.Now().UnixMilli()
	result, err := registerMCPOAuthBrokerClient.Run(ctx, client, []string{s.key(indexKey), s.key(clientKey)}, now, limit, ttl.Milliseconds(), value, now+ttl.Milliseconds(), member).Int64()
	if err != nil {
		return fmt.Errorf("atomically register OAuth broker client: %w", err)
	}
	switch result {
	case 1:
		return nil
	case 0:
		return errMCPOAuthBrokerClientLimit
	case -1:
		return errMCPOAuthBrokerStoreCollision
	default:
		return fmt.Errorf("atomically register OAuth broker client: unexpected result %d", result)
	}
}

var claimMCPOAuthBrokerClient = redis.NewScript(`
if redis.call("EXISTS", KEYS[2]) == 1 then
  return nil
end
local value = redis.call("GET", KEYS[1])
if not value then
  return nil
end
redis.call("RENAME", KEYS[1], KEYS[2])
return value
`)

// ClaimClient atomically makes a mapping unavailable to authorization and to
// competing management requests while preserving its original TTL.
func (s *redisMCPOAuthBrokerStore) ClaimClient(ctx context.Context, clientKey, claimKey string) ([]byte, bool, error) {
	client, err := s.client()
	if err != nil {
		return nil, false, err
	}
	value, err := claimMCPOAuthBrokerClient.Run(ctx, client, []string{s.key(clientKey), s.key(claimKey)}).Text()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("atomically claim OAuth broker client: %w", err)
	}
	return []byte(value), true, nil
}

var restoreMCPOAuthBrokerClient = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
  return 0
end
if redis.call("RENAMENX", KEYS[1], KEYS[2]) == 0 then
  return -1
end
return 1
`)

func (s *redisMCPOAuthBrokerStore) RestoreClient(ctx context.Context, claimKey, clientKey string) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	result, err := restoreMCPOAuthBrokerClient.Run(ctx, client, []string{s.key(claimKey), s.key(clientKey)}).Int64()
	if err != nil {
		return fmt.Errorf("atomically restore OAuth broker client: %w", err)
	}
	if result != 1 {
		return errors.New("OAuth broker client claim cannot be restored")
	}
	return nil
}

var replaceClaimedMCPOAuthBrokerClient = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 or redis.call("EXISTS", KEYS[2]) == 1 then
  return 0
end
redis.call("SET", KEYS[2], ARGV[1], "PX", ARGV[2])
redis.call("DEL", KEYS[1])
redis.call("ZADD", KEYS[3], ARGV[3], ARGV[4])
redis.call("PEXPIRE", KEYS[3], ARGV[2])
return 1
`)

// ReplaceClaimedClient atomically publishes a rotated sealed mapping and
// releases the management claim. A successful update renews the registration
// lifetime and its limit-index entry together.
func (s *redisMCPOAuthBrokerStore) ReplaceClaimedClient(ctx context.Context, claimKey, clientKey, indexKey, member string, value []byte, ttl time.Duration) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	if claimKey == "" || clientKey == "" || indexKey == "" || member == "" || len(value) == 0 || ttl <= 0 {
		return errors.New("MCP OAuth broker client replacement has invalid storage parameters")
	}
	now := time.Now().UnixMilli()
	result, err := replaceClaimedMCPOAuthBrokerClient.Run(ctx, client,
		[]string{s.key(claimKey), s.key(clientKey), s.key(indexKey)}, value, ttl.Milliseconds(), now+ttl.Milliseconds(), member).Int64()
	if err != nil {
		return fmt.Errorf("atomically replace OAuth broker client: %w", err)
	}
	if result != 1 {
		return errors.New("OAuth broker claimed client cannot be replaced")
	}
	return nil
}

var finishMCPOAuthBrokerClientDeletion = redis.NewScript(`
redis.call("DEL", KEYS[1], KEYS[2])
redis.call("ZREM", KEYS[3], ARGV[1])
return 1
`)

func (s *redisMCPOAuthBrokerStore) FinishClientDeletion(ctx context.Context, claimKey, clientKey, indexKey, member string) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	if err := finishMCPOAuthBrokerClientDeletion.Run(ctx, client,
		[]string{s.key(claimKey), s.key(clientKey), s.key(indexKey)}, member).Err(); err != nil {
		return fmt.Errorf("atomically finish OAuth broker client deletion: %w", err)
	}
	return nil
}
