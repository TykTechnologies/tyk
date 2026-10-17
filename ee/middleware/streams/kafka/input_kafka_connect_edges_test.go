package kafka

import (
	"context"
	"testing"

	"github.com/Jeffail/shutdown"
	"github.com/stretchr/testify/require"
	"github.com/warpstreamlabs/bento/public/service"
)

func TestKafkaConnectReturnsForExistingAndStoppedLifecycle(t *testing.T) {
	connected := &franzKafkaReader{}
	connected.storeBatchChan(make(chan batchWithAckFn))
	require.NoError(t, connected.Connect(context.Background()))

	stopped := &franzKafkaReader{shutSig: shutdown.NewSignaller()}
	stopped.shutSig.TriggerSoftStop()
	require.ErrorIs(t, stopped.Connect(context.Background()), service.ErrEndOfInput)
}

func TestKafkaExternalAckConnectFailsClosedBeforeBrokerDial(t *testing.T) {
	base := defaultAcknowledgmentConfig()
	base.Mode = AcknowledgmentModeExternal
	reader := &franzKafkaReader{acknowledgment: base, shutSig: shutdown.NewSignaller()}
	require.ErrorContains(t, reader.Connect(context.Background()), "component_id")

	reader.acknowledgment.ComponentID = "connect-edge-missing-keys"
	require.ErrorContains(t, reader.Connect(context.Background()), "signing keys")

	const componentID = "connect-edge-missing-transport"
	provider, err := NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("connect-edge-signing-secret-32-bytes")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(componentID, provider))
	t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(componentID) })
	reader.acknowledgment.ComponentID = componentID
	reader.acknowledgment.Routing = "distributed"
	reader.consumerGroup = "workers"
	require.ErrorContains(t, reader.Connect(context.Background()), "distributed acknowledgment transport")
	require.Nil(t, reader.ackController, "failed setup must release the partially created controller")
}
