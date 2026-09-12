package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/storage"
)

var errMCPOAuthBrokerStoreCollision = errors.New("MCP OAuth broker key already exists")

// mcpOAuthBrokerStore is deliberately smaller than storage.Handler. OAuth
// transaction values must support a real atomic consume operation so callback,
// code, and refresh replay cannot win on different Gateway instances.
type mcpOAuthBrokerStore interface {
	Put(context.Context, string, []byte, time.Duration) error
	Get(context.Context, string) ([]byte, bool, error)
	Consume(context.Context, string) ([]byte, bool, error)
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
