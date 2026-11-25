//go:build ee || dev

// Provides StreamingMiddleware
package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	streamkafka "github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
	"github.com/gorilla/mux"
	"net/http"
	"strings"
)

const kafkaOffsetResetAuthorizationHeader = "x-tyk-kafka-reset-authorization"

func init() {
	registerStreamingControlEndpoints = func(router *mux.Router, gw *Gateway) {
		wrap := func(factory func(*streamkafka.ControllerRegistry, streamkafka.ControllerKey, streamkafka.HandlerLimits) http.Handler, class string) http.HandlerFunc {
			initial := gw.GetConfig().KafkaControlRateLimits
			// Unknown components share one bounded fallback bucket. Valid registered
			// components use lifecycle-scoped buckets below.
			fallback := streamkafka.NewResetRateLimiter(float64(initial.ResetRequestsPerSecond), initial.ResetBurst)
			return func(w http.ResponseWriter, r *http.Request) {
				cfg := gw.GetConfig()
				actorKind := "control-api-owner"
				var actorMaterial []string
				if ref := cfg.KafkaOffsetResetAuthorization.SecretRef; ref != "" {
					expected, ok := cfg.Secrets[ref]
					provided := r.Header.Get(kafkaOffsetResetAuthorizationHeader)
					if !ok || expected == "" || provided == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
						http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
						return
					}
					actorKind, actorMaterial = "dedicated-reset", []string{ref, expected}
				}
				actorHash := kafkaResetAuditActorHash(cfg.Secret, actorKind, actorMaterial...)
				r = r.WithContext(streamkafka.WithResetAuditActorHash(r.Context(), actorHash))
				vars := mux.Vars(r)
				component := vars["componentID"]
				if !strings.HasPrefix(component, vars["apiID"]+"_"+vars["streamID"]+"_") {
					http.NotFound(w, r)
					return
				}
				key := streamkafka.ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: component}
				rateLimits := cfg.KafkaControlRateLimits
				limiter, ok := streamkafka.GlobalControllerRegistry.RateLimiter(key, class, float64(rateLimits.ResetRequestsPerSecond), rateLimits.ResetBurst)
				if !ok {
					limiter = fallback
				}
				factory(streamkafka.GlobalControllerRegistry, key, streamkafka.HandlerLimits{
					RateLimiter: limiter,
					RateLimitConfig: func() (float64, int) {
						current := gw.GetConfig().KafkaControlRateLimits
						return float64(current.ResetRequestsPerSecond), current.ResetBurst
					},
				}).ServeHTTP(w, r)
			}
		}
		router.HandleFunc("/streams/{apiID}/{streamID}/kafka/{componentID}/offset/reset/plan", wrap(streamkafka.NewResetPlanHandler, "reset-plan")).Methods(http.MethodPost)
		router.HandleFunc("/streams/{apiID}/{streamID}/kafka/{componentID}/offset/reset/execute", wrap(streamkafka.NewResetExecuteHandler, "reset-execute")).Methods(http.MethodPost)
	}
}

func kafkaResetAuditActorHash(gatewaySecret, kind string, material ...string) string {
	mac := hmac.New(sha256.New, []byte(gatewaySecret))
	for _, field := range append([]string{"tyk:kafka-reset-actor:v1", kind}, material...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(field))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (gw *Gateway) RecordKafkaStreams(ctx context.Context, snapshot streams.KafkaTelemetrySnapshot) {
	if gw.MetricInstruments == nil {
		return
	}
	gw.MetricInstruments.RecordKafkaStream(ctx, snapshot.APIID, snapshot.StreamID, snapshot.ComponentID, snapshot.Deltas, snapshot.State)
}

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	spec := baseMid.Spec
	streamSpec := streams.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.StripListenPath)

	streamAnalyticsFactory := NewStreamAnalyticsFactory(baseMid.logger.Dup(), baseMid.Gw, spec)
	streamMw := streams.NewMiddleware(baseMid.Gw, baseMid, streamSpec, streamAnalyticsFactory)
	return WrapMiddleware(baseMid, streamMw)
}
