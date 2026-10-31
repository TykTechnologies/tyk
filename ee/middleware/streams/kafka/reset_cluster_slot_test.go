package kafka

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func redisHashTag(key string) string {
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return key
	}
	end := strings.IndexByte(key[start+1:], '}')
	if end <= 0 {
		return key
	}
	return key[start+1 : start+1+end]
}

func TestRedisResetTransactionKeysShareClusterSlot(t *testing.T) {
	store := &RedisResetStateStore{prefix: "tyk:kafka:reset:component-a"}
	planA := store.keys("plan-a")
	planB := store.keys("plan-b")
	members, barrier, acknowledgements := store.coordinationKeys("consumer-group")
	participantLease := resetParticipantLeaseKey(members, "gateway-a")

	wantTag := redisHashTag(planA.lease)
	require.NotEmpty(t, wantTag)
	for _, key := range []string{
		planA.plan, planA.execution, planA.lease, planA.generation,
		planB.plan, planB.execution, planB.lease, planB.generation,
		members, barrier, acknowledgements, participantLease,
	} {
		require.Equal(t, wantTag, redisHashTag(key), "transaction key %q must share the component reset slot", key)
	}
	require.NotEqual(t, planA.plan, planB.plan, "plan state remains isolated outside the common hash tag")
	otherComponent := (&RedisResetStateStore{prefix: "tyk:kafka:reset:component-b"}).keys("plan-a")
	require.NotEqual(t, wantTag, redisHashTag(otherComponent.lease), "independent components must not share one global hot slot")
}
