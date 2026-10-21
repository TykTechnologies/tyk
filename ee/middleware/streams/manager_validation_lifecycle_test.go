package streams

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/TykTechnologies/tyk/config"
)

type lifecycleInput struct{ connects, closes *atomic.Int32 }

func (i *lifecycleInput) Connect(context.Context) error { i.connects.Add(1); return nil }
func (*lifecycleInput) ReadBatch(ctx context.Context) (service.MessageBatch, service.AckFunc, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}
func (i *lifecycleInput) Close(context.Context) error { i.closes.Add(1); return nil }

func TestManagerValidationDoesNotConnectAndBackgroundLifecycleIsSingular(t *testing.T) {
	const component = "tyk_manager_lifecycle_probe"
	var connects, closes atomic.Int32
	err := service.RegisterBatchInput(component, service.NewConfigSpec(), func(*service.ParsedConfig, *service.Resources) (service.BatchInput, error) {
		return &lifecycleInput{connects: &connects, closes: &closes}, nil
	})
	require.NoError(t, err)
	gateway := &kafkaProvisioningGateway{conf: configForLifecycleTest()}
	middleware := &Middleware{Spec: &APISpec{APIID: "lifecycle-api"}, Gw: gateway, base: kafkaProvisioningBase{logger: testLogger()}}
	config := &StreamsConfig{Streams: map[string]any{"background": map[string]interface{}{
		"input": map[string]interface{}{component: map[string]interface{}{}}, "output": map[string]interface{}{"drop": map[string]interface{}{}},
	}}}
	validator := &Manager{muxer: mux.NewRouter(), mw: middleware, validateOnly: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
	validator.initStreams(nil, config)
	require.Zero(t, connects.Load(), "schema validation must not call component Connect")
	countStreams := func(manager *Manager) int {
		count := 0
		manager.streams.Range(func(_, _ any) bool { count++; return true })
		return count
	}
	require.Zero(t, countStreams(validator))

	startRuntime := func() *Manager {
		manager := &Manager{muxer: mux.NewRouter(), mw: middleware, background: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
		manager.initStreams(nil, config)
		return manager
	}
	runtime := startRuntime()
	require.Eventually(t, func() bool { return connects.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, countStreams(runtime), "one background connector is started")
	require.NoError(t, runtime.removeStream("lifecycle-api_background"))
	require.Eventually(t, func() bool { return closes.Load() == 1 }, 5*time.Second, 10*time.Millisecond, "unload closes the runtime connector")

	reloaded := startRuntime()
	require.Eventually(t, func() bool { return connects.Load() == 2 }, 5*time.Second, 10*time.Millisecond, "reload starts exactly one replacement")
	require.Equal(t, 1, countStreams(reloaded))
	require.NoError(t, reloaded.removeStream("lifecycle-api_background"))
	require.Eventually(t, func() bool { return closes.Load() == 2 }, 5*time.Second, 10*time.Millisecond, "replacement is also closed")
}

func configForLifecycleTest() config.Config { return config.Config{} }
