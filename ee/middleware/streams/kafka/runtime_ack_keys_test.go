package kafka

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRuntimeAckKeyRegistrySharesKeysWithoutYAMLSecrets(t *testing.T) {
	provider, err := NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("01234567890123456789012345678901")})
	require.NoError(t, err)
	registry := NewRuntimeAckKeyRegistry()
	require.NoError(t, registry.Configure("component", provider))
	first, err := registry.Resolve(context.Background(), "component", "scope")
	require.NoError(t, err)
	second, err := registry.Resolve(context.Background(), "component", "scope")
	require.NoError(t, err)
	token, err := first.Sign(AckClaims{Scope: "scope", Topic: "topic", Partition: 0, Offset: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	_, err = second.Verify(token, "scope")
	require.NoError(t, err)
	registry.Remove("component")
	_, err = registry.Resolve(context.Background(), "component", "scope")
	require.Error(t, err)
}

func TestRuntimeAckKeyRegistrationFencesStaleLifecycleOwner(t *testing.T) {
	registry := NewRuntimeAckKeyRegistry()
	firstProvider, err := NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("01234567890123456789012345678901")})
	require.NoError(t, err)
	first, err := registry.ConfigureRegistrationWithInvalidation("component", firstProvider, false)
	require.NoError(t, err)
	secondProvider, err := NewSharedAckSigningKeyProvider("v2", map[string][]byte{"v2": []byte("abcdefghijklmnopqrstuvwxyzABCDEF")})
	require.NoError(t, err)
	second, err := registry.ConfigureRegistrationWithInvalidation("component", secondProvider, true)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.False(t, first.Remove())
			_, resolveErr := registry.Resolve(context.Background(), "component", "scope")
			require.NoError(t, resolveErr)
		}()
	}
	wg.Wait()
	require.True(t, second.Remove())
	_, err = registry.Resolve(context.Background(), "component", "scope")
	require.Error(t, err, "current unload removes signing secrets")
}
