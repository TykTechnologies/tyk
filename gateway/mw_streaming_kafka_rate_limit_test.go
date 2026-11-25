//go:build ee || dev

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	streamkafka "github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
)

type gatewayRateLimitOffsetController struct{}

func (*gatewayRateLimitOffsetController) PlanReset(context.Context, streamkafka.ResetPlanRequest) (streamkafka.ResetPlan, error) {
	return streamkafka.ResetPlan{ID: "rate-plan"}, nil
}

func (*gatewayRateLimitOffsetController) ExecuteReset(context.Context, streamkafka.ResetExecuteRequest) (streamkafka.ResetExecution, error) {
	return streamkafka.ResetExecution{ID: "rate-execution", Status: "completed"}, nil
}

func TestKafkaResetGatewayRateLimitClassesAndReload(t *testing.T) {
	ts := StartTest(func(cfg *config.Config) {
		cfg.KafkaControlRateLimits.ResetRequestsPerSecond = 1
		cfg.KafkaControlRateLimits.ResetBurst = 1
	})
	t.Cleanup(ts.Close)
	const apiID, streamID = "rate-api", "rate-stream"
	componentID := apiID + "_" + streamID + "_input"
	key := streamkafka.ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}
	register := func() *streamkafka.ControllerRegistration {
		registration, err := streamkafka.GlobalControllerRegistry.Register(key, streamkafka.Controllers{Offsets: &gatewayRateLimitOffsetController{}})
		require.NoError(t, err)
		return registration
	}
	registration := register()
	t.Cleanup(func() { registration.Unregister() })
	base := fmt.Sprintf("/tyk/streams/%s/%s/kafka/%s/offset/reset", apiID, streamID, componentID)
	planPayload := `{"consumer_group":"group","reason":"rate test","targets":[{"topic":"topic","partition":0,"offset":0}]}`

	response, body := kafkaGatewayControlPost(t, ts.URL+base+"/plan", ts.Gw.GetConfig().Secret, planPayload)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	response, body = kafkaGatewayControlPost(t, ts.URL+base+"/plan", ts.Gw.GetConfig().Secret, planPayload)
	require.Equal(t, http.StatusTooManyRequests, response.StatusCode, string(body))
	require.Equal(t, "1", response.Header.Get("Retry-After"))

	response, body = kafkaGatewayControlPost(t, ts.URL+base+"/execute", ts.Gw.GetConfig().Secret, `{"plan_id":"rate-plan"}`)
	require.Equal(t, http.StatusAccepted, response.StatusCode, "execute has an independent control class: %s", body)
	response, body = kafkaGatewayControlPost(t, ts.URL+base+"/execute", ts.Gw.GetConfig().Secret, `{"plan_id":"rate-plan"}`)
	require.Equal(t, http.StatusTooManyRequests, response.StatusCode, string(body))
	require.Equal(t, "1", response.Header.Get("Retry-After"))

	updated := ts.Gw.GetConfig()
	updated.KafkaControlRateLimits.ResetRequestsPerSecond = 1_000_000
	updated.KafkaControlRateLimits.ResetBurst = 1_000_000
	ts.Gw.SetConfig(updated, true)
	response, _ = kafkaGatewayControlPost(t, ts.URL+base+"/plan", ts.Gw.GetConfig().Secret, planPayload)
	require.Equal(t, http.StatusTooManyRequests, response.StatusCode, "config change must preserve exhausted allowance")
	time.Sleep(2 * time.Millisecond)
	response, body = kafkaGatewayControlPost(t, ts.URL+base+"/plan", ts.Gw.GetConfig().Secret, planPayload)
	require.Equal(t, http.StatusOK, response.StatusCode, "existing limiter did not adopt live config: %s", body)

	// Controller registration is the component lifecycle lease. Unload removes
	// its limiter state; a replacement component begins with a fresh bucket.
	require.True(t, registration.Unregister())
	registration = register()
	response, body = kafkaGatewayControlPost(t, ts.URL+base+"/plan", ts.Gw.GetConfig().Secret, planPayload)
	require.Equal(t, http.StatusOK, response.StatusCode, "replacement component retained the old limiter: %s", body)
}
