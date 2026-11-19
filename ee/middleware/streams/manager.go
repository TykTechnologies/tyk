package streams

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
	"github.com/gorilla/mux"
)

const (
	defaultKafkaAckRouterMaxEntries = 100_000
	defaultKafkaAckRouterMaxBytes   = 256 << 20
)

// Manager is responsible for creating a single stream.
type Manager struct {
	streams                 sync.Map
	routeLock               sync.Mutex
	muxer                   *mux.Router
	controlPaths            sync.Map
	transportRegistrations  sync.Map // streamFullID to []*kafka.RuntimeAckTransportRegistration
	resetStoreRegistrations sync.Map // streamFullID to []*kafka.RuntimeResetStateStoreRegistration
	keyRegistrations        sync.Map // streamFullID to []*kafka.RuntimeAckKeyRegistration
	localSingletonLeases    sync.Map // streamFullID to []*kafka.LocalSingletonLease
	telemetryCancels        sync.Map // streamFullID to []context.CancelFunc
	mw                      *Middleware
	validateOnly            bool
	background              bool
	listenPaths             []string
	activityCounter         atomic.Int32 // Counts active subscriptions, requests.
	analyticsFactoryMu      sync.RWMutex
	analyticsFactory        StreamAnalyticsFactory
}

func (sm *Manager) initStreams(r *http.Request, config *StreamsConfig) {
	// Clear existing routes for this consumer group
	sm.muxer = mux.NewRouter()

	for streamID, streamConfig := range config.Streams {
		sm.setUpOrDryRunStream(streamConfig, streamID)
	}

	// If it is default stream manager, init muxer
	if r == nil {
		for _, path := range sm.listenPaths {
			sm.muxer.HandleFunc(path, func(_ http.ResponseWriter, _ *http.Request) {
				// Dummy handler
			})
		}
	}
}

func (sm *Manager) setUpOrDryRunStream(streamConfig any, streamID string) {
	if streamMap, ok := streamConfig.(map[string]interface{}); ok {
		componentIDs := PrepareKafkaAcknowledgmentComponents(streamMap, sm.mw.Spec.APIID, streamID)
		var telemetryTransport kafka.DurableAckTransport
		if sm.validateOnly {
			stream := NewStream(sm.mw.allowedUnsafe, sm.mw.Logger())
			if err := stream.Validate(streamMap, nil); err != nil {
				sm.mw.Logger().WithError(err).Errorf("Invalid stream %s", streamID)
			}
			return
		}
		distributedComponents := DistributedKafkaAcknowledgmentComponents(streamMap)
		localComponents := LocalKafkaAcknowledgmentComponents(streamMap)
		streamFullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)
		setupSucceeded := false
		defer func() {
			if !setupSucceeded {
				sm.removeTransportRegistrations(streamFullID)
			}
		}()
		if len(localComponents) > 0 {
			redisClient, err := sm.mw.Gw.StreamingRedisClient()
			if err != nil {
				sm.mw.Logger().WithError(err).Error("routing: local requires the Gateway-managed Redis singleton lease")
				return
			}
			leases := make([]*kafka.LocalSingletonLease, 0, len(localComponents))
			for _, componentID := range localComponents {
				lease, leaseErr := kafka.AcquireLocalSingletonLease(context.Background(), redisClient, componentID, 15*time.Second)
				if leaseErr != nil {
					for _, existing := range leases {
						existing.Close()
					}
					sm.mw.Logger().WithError(leaseErr).Errorf("Failed to acquire routing:local singleton lease for %s", componentID)
					return
				}
				leases = append(leases, lease)
			}
			sm.localSingletonLeases.Store(streamFullID, leases)
		}
		if len(distributedComponents) > 0 && sm.background {
			redisClient, err := sm.mw.Gw.StreamingRedisClient()
			if err != nil {
				sm.mw.Logger().WithError(err).Error("Failed to obtain Gateway-managed Redis client for distributed Kafka acknowledgments")
				return
			}
			transport, err := kafka.NewRedisDurableAckTransport(redisClient, kafka.RedisDurableAckOptions{
				MaxEntries:       defaultKafkaAckRouterMaxEntries,
				MaxBytes:         defaultKafkaAckRouterMaxBytes,
				MaxGlobalEntries: defaultKafkaAckRouterMaxEntries,
				MaxGlobalBytes:   defaultKafkaAckRouterMaxBytes,
			})
			if err != nil {
				sm.mw.Logger().WithError(err).Error("Failed to initialize distributed Kafka acknowledgment transport")
				return
			}
			telemetryTransport = transport
			registrations := make([]*kafka.RuntimeAckTransportRegistration, 0, len(distributedComponents))
			resetRegistrations := make([]*kafka.RuntimeResetStateStoreRegistration, 0, len(distributedComponents))
			for _, componentID := range distributedComponents {
				componentDigest := sha256.Sum256([]byte(componentID))
				resetStore, resetErr := kafka.NewRedisResetStateStore(redisClient, fmt.Sprintf("tyk:kafka:reset:%x", componentDigest[:12]))
				if resetErr != nil {
					for _, existing := range registrations {
						existing.Remove()
					}
					for _, existing := range resetRegistrations {
						existing.Remove()
					}
					sm.mw.Logger().WithError(resetErr).Errorf("Failed to initialize distributed reset state store for %s", componentID)
					return
				}
				resetStore.SetAuditIdentity(sm.mw.Spec.APIID, streamID, componentID)
				if recorder, ok := sm.mw.Gw.(KafkaTelemetryRecorder); ok {
					resetStore.SetAuditObserver(func(event kafka.ResetAuditEvent) {
						deltas := map[string]uint64{}
						switch event.Outcome {
						case "planned":
							deltas["reset_plans"] = 1
						case "completed":
							deltas["reset_executions"] = 1
						case "partial_failed":
							deltas["reset_executions"], deltas["reset_failures"] = 1, 1
						case "expired_barrier_recovered":
							deltas["reset_failures"] = 1
						}
						if strings.HasSuffix(event.Outcome, "_failed") {
							deltas["reset_failures"] = 1
						}
						if len(deltas) > 0 {
							recorder.RecordKafkaStreams(context.Background(), KafkaTelemetrySnapshot{APIID: sm.mw.Spec.APIID, StreamID: streamID, ComponentID: event.ComponentID, Deltas: deltas})
						}
					})
				}
				registration, configureErr := kafka.GlobalRuntimeAckTransportRegistry.Configure(componentID, kafka.StaticDurableAckTransportProvider{Transport: transport})
				if configureErr != nil {
					for _, existing := range registrations {
						existing.Remove()
					}
					sm.mw.Logger().WithError(configureErr).Errorf("Failed to configure distributed acknowledgment transport for %s", componentID)
					return
				}
				registrations = append(registrations, registration)
				resetRegistration, configureErr := kafka.GlobalRuntimeResetStateStoreRegistry.Configure(componentID, kafka.StaticResetStateStoreProvider{Store: resetStore})
				if configureErr != nil {
					registration.Remove()
					for _, existing := range registrations[:len(registrations)-1] {
						existing.Remove()
					}
					for _, existing := range resetRegistrations {
						existing.Remove()
					}
					sm.mw.Logger().WithError(configureErr).Errorf("Failed to configure distributed reset state store for %s", componentID)
					return
				}
				resetRegistrations = append(resetRegistrations, resetRegistration)
			}
			sm.transportRegistrations.Store(streamFullID, registrations)
			sm.resetStoreRegistrations.Store(streamFullID, resetRegistrations)
		}
		if len(componentIDs) > 0 {
			provider, err := gatewayAckSigningProvider(sm.mw.Gw.GetConfig(), streamMap)
			if err != nil {
				sm.removeTransportRegistrations(streamFullID)
				sm.mw.Logger().WithError(err).Error("Failed to initialize Kafka acknowledgment signing keys")
				return
			}
			keyRegistrations := make([]*kafka.RuntimeAckKeyRegistration, 0, len(componentIDs))
			for _, componentID := range componentIDs {
				registration, configureErr := kafka.GlobalRuntimeAckKeyRegistry.ConfigureRegistrationWithInvalidation(componentID, provider, sm.mw.Gw.GetConfig().KafkaAcknowledgmentSigning.ForceInvalidateLiveTokens)
				if configureErr != nil {
					for _, existing := range keyRegistrations {
						existing.Remove()
					}
					sm.mw.Logger().WithError(configureErr).Errorf("Failed to configure Kafka acknowledgment keys for %s", componentID)
					return
				}
				keyRegistrations = append(keyRegistrations, registration)
			}
			sm.keyRegistrations.Store(streamFullID, keyRegistrations)
		}
		httpPaths := GetHTTPPaths(streamMap)

		if sm.background {
			if len(httpPaths) == 0 {
				err := sm.createStream(streamID, streamMap)
				if err != nil {
					sm.mw.Logger().WithError(err).Errorf("Error creating stream %s", streamID)
					sm.removeTransportRegistrations(fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID))
				}
			}
		} else {
			err := sm.createStream(streamID, streamMap)
			if err != nil {
				sm.mw.Logger().WithError(err).Errorf("Error creating stream %s", streamID)
				sm.removeTransportRegistrations(fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID))
			}
		}
		sm.listenPaths = append(sm.listenPaths, httpPaths...)

		for index, componentID := range componentIDs {
			key := kafka.ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}
			rateLimits := sm.mw.Gw.GetConfig().KafkaControlRateLimits
			handler := kafka.NewAcknowledgmentHandler(kafka.GlobalControllerRegistry, key, kafka.HandlerLimits{RateLimiter: kafka.NewAcknowledgmentRateLimiter(
				float64(rateLimits.AcknowledgmentRequestsPerSecond), rateLimits.AcknowledgmentBurst,
			), RateLimitConfig: func() (float64, int) {
				current := sm.mw.Gw.GetConfig().KafkaControlRateLimits
				return float64(current.AcknowledgmentRequestsPerSecond), current.AcknowledgmentBurst
			}})
			statusHandler := kafka.NewAcknowledgmentStatusHandler(kafka.GlobalControllerRegistry, key)
			componentPath := fmt.Sprintf("/%s/kafka/%s/ack", streamID, url.PathEscape(componentID))
			statusPath := fmt.Sprintf("/%s/kafka/%s/status", streamID, url.PathEscape(componentID))
			sm.muxer.Handle(componentPath, handler).Methods(http.MethodPost)
			sm.muxer.Handle(statusPath, statusHandler).Methods(http.MethodGet)
			sm.listenPaths = append(sm.listenPaths, componentPath, statusPath)
			sm.controlPaths.Store(strings.TrimPrefix(componentPath, "/"), struct{}{})
			sm.controlPaths.Store(strings.TrimPrefix(statusPath, "/"), struct{}{})
			if len(componentIDs) == 1 && index == 0 {
				ackPath := fmt.Sprintf("/%s/kafka/ack", streamID)
				shortStatusPath := fmt.Sprintf("/%s/kafka/status", streamID)
				sm.muxer.Handle(ackPath, handler).Methods(http.MethodPost)
				sm.muxer.Handle(shortStatusPath, statusHandler).Methods(http.MethodGet)
				sm.listenPaths = append(sm.listenPaths, ackPath, shortStatusPath)
				sm.controlPaths.Store(strings.TrimPrefix(ackPath, "/"), struct{}{})
				sm.controlPaths.Store(strings.TrimPrefix(shortStatusPath, "/"), struct{}{})
			}
			sm.startKafkaTelemetry(streamID, componentID, key, telemetryTransport)
		}
		setupSucceeded = true
	}
}

func gatewayAckSigningProvider(cfg config.Config, stream map[string]interface{}) (*kafka.SharedAckSigningKeyProvider, error) {
	signing := cfg.KafkaAcknowledgmentSigning
	if signing.ActiveKeyID == "" && len(signing.Keys) == 0 {
		secret := []byte(cfg.Secret)
		if len(secret) < 32 {
			return nil, fmt.Errorf("Kafka external acknowledgment requires a Gateway secret of at least 32 bytes or explicit acknowledgment signing keys")
		}
		if cfg.Secret == config.Default.Secret {
			return nil, fmt.Errorf("Kafka external acknowledgment refuses the default Gateway secret; configure a unique secret or explicit acknowledgment signing keys")
		}
		root := sha256.Sum256([]byte(cfg.Secret))
		return kafka.NewSharedAckSigningKeyProvider("gateway-secret-v1", map[string][]byte{"gateway-secret-v1": root[:]})
	}
	if signing.ActiveKeyID == "" || len(signing.Keys) == 0 {
		return nil, fmt.Errorf("Kafka acknowledgment signing active key and key references must be configured together")
	}
	tokenTTL := 24 * time.Hour
	if input, ok := stream["input"].(map[string]interface{}); ok {
		if kc, ok := input["tyk_kafka"].(map[string]interface{}); ok {
			if ack, ok := kc["acknowledgment"].(map[string]interface{}); ok {
				if raw, ok := ack["token_ttl"].(string); ok {
					if parsed, err := time.ParseDuration(raw); err == nil {
						tokenTTL = parsed
					}
				}
			}
		}
	}
	drain := time.Duration(signing.ShutdownDrainSeconds) * time.Second
	if drain <= 0 {
		drain = 30 * time.Second
	}
	if time.Duration(signing.RotationOverlapSeconds)*time.Second < tokenTTL+drain {
		return nil, fmt.Errorf("Kafka acknowledgment signing overlap must be at least token TTL plus shutdown drain")
	}
	secrets := make(map[string][]byte, len(signing.Keys))
	for id, ref := range signing.Keys {
		value, ok := cfg.Secrets[ref]
		if !ok {
			return nil, fmt.Errorf("Kafka acknowledgment signing secret reference %q is missing", ref)
		}
		secrets[id] = []byte(value)
	}
	return kafka.NewSharedAckSigningKeyProvider(signing.ActiveKeyID, secrets)
}

// removeStream removes a stream
func (sm *Manager) removeStream(streamID string) error {
	sm.removeTransportRegistrations(fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID))
	if streamValue, exists := sm.streams.Load(streamID); exists {
		stream, ok := streamValue.(*Stream)
		if !ok {
			return fmt.Errorf("stream %s is not a valid stream", streamID)
		}
		err := stream.Stop()
		if err != nil {
			return err
		}
		sm.streams.Delete(streamID)
	} else {
		return fmt.Errorf("stream %s does not exist", streamID)
	}
	return nil
}

func (sm *Manager) removeTransportRegistrations(streamFullID string) {
	if value, ok := sm.keyRegistrations.LoadAndDelete(streamFullID); ok {
		for _, registration := range value.([]*kafka.RuntimeAckKeyRegistration) {
			registration.Remove()
		}
	}
	if value, ok := sm.localSingletonLeases.LoadAndDelete(streamFullID); ok {
		for _, lease := range value.([]*kafka.LocalSingletonLease) {
			lease.Close()
		}
	}
	if value, ok := sm.telemetryCancels.LoadAndDelete(streamFullID); ok {
		for _, cancel := range value.([]context.CancelFunc) {
			cancel()
		}
	}
	value, ok := sm.transportRegistrations.LoadAndDelete(streamFullID)
	if ok {
		for _, registration := range value.([]*kafka.RuntimeAckTransportRegistration) {
			registration.Remove()
		}
	}
	resetValue, resetOK := sm.resetStoreRegistrations.LoadAndDelete(streamFullID)
	if resetOK {
		for _, registration := range resetValue.([]*kafka.RuntimeResetStateStoreRegistration) {
			registration.Remove()
		}
	}
}

func (sm *Manager) startKafkaTelemetry(streamID, componentID string, key kafka.ControllerKey, transport kafka.DurableAckTransport) {
	recorder, ok := sm.mw.Gw.(KafkaTelemetryRecorder)
	if !ok || sm.validateOnly {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	fullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)
	value, _ := sm.telemetryCancels.LoadOrStore(fullID, []context.CancelFunc{})
	cancels := append(value.([]context.CancelFunc), cancel)
	sm.telemetryCancels.Store(fullID, cancels)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		var previous kafka.ExternalAckMetricsSnapshot
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				status, found := kafka.GlobalControllerRegistry.StatusSnapshot(key, 128)
				if !found {
					continue
				}
				current := status.Metrics
				var routerActive, routerPending, routerDead int64
				if transport != nil {
					for _, partition := range status.Partitions {
						stats := transport.Stats(ctx, kafka.AckRoute{Key: key, Topic: partition.Topic, Partition: partition.Partition})
						routerActive += int64(stats.Active)
						routerPending += int64(stats.Pending)
						routerDead += int64(stats.DeadLetters)
					}
				}
				delta := func(now, before uint64) uint64 {
					if now < before {
						return now
					}
					return now - before
				}
				recorder.RecordKafkaStreams(ctx, KafkaTelemetrySnapshot{APIID: sm.mw.Spec.APIID, StreamID: streamID, ComponentID: componentID,
					Deltas: map[string]uint64{"delivered": delta(current.Delivered, previous.Delivered), "ack_applied": delta(current.AckApplied, previous.AckApplied), "ack_invalid": delta(current.AckInvalid, previous.AckInvalid), "ack_stale": delta(current.AckStale, previous.AckStale), "ack_expired": delta(current.AckExpired, previous.AckExpired), "commit_attempts": delta(current.CommitAttempts, previous.CommitAttempts), "commit_failures": delta(current.CommitFailures, previous.CommitFailures)},
					State:  map[string]int64{"in_flight": int64(status.InFlight), "in_flight_bytes": status.InFlightBytes, "pending_commits": int64(status.PendingCommits), "paused_partitions": int64(countPausedPartitions(status.Partitions)), "router_backlog": routerActive, "router_pending": routerPending, "router_dead_letters": routerDead}})
				previous = current
			}
		}
	}()
}

func countPausedPartitions(partitions []kafka.ExternalAckPartitionStatus) int {
	count := 0
	for _, partition := range partitions {
		if partition.Paused {
			count++
		}
	}
	return count
}

func (sm *Manager) closeTransportRegistrations() {
	sm.transportRegistrations.Range(func(key, _ any) bool {
		sm.removeTransportRegistrations(key.(string))
		return true
	})
}

func (sm *Manager) isControlPath(path string) bool {
	_, ok := sm.controlPaths.Load(strings.TrimPrefix(path, "/"))
	return ok
}

// createStream creates a new stream
func (sm *Manager) createStream(streamID string, config map[string]interface{}) error {
	streamFullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)
	sm.mw.Logger().Debugf("Creating stream: %s", streamFullID)

	// add logger to config
	config["logger"] = map[string]interface{}{
		"level":         "INFO",
		"format":        "json",
		"add_timestamp": true,
		"static_fields": map[string]interface{}{
			"stream": streamID,
		},
	}

	stream := NewStream(sm.mw.allowedUnsafe, sm.mw.Logger())
	err := stream.Start(config, &HandleFuncAdapter{
		StreamMiddleware: sm.mw,
		StreamID:         streamFullID,
		Muxer:            sm.muxer,
		StreamManager:    sm,
		// child logger is necessary to prevent race condition
		Logger: sm.mw.Logger().WithField("stream", streamFullID),
	})
	if err != nil {
		sm.mw.Logger().Errorf("Failed to start stream %s: %v", streamFullID, err)
		return err
	}

	sm.streams.Store(streamFullID, stream)
	sm.mw.Logger().Infof("Successfully created stream: %s", streamFullID)

	return nil
}

func (sm *Manager) hasPath(path string) bool {
	for _, p := range sm.listenPaths {
		if strings.TrimPrefix(path, "/") == strings.TrimPrefix(p, "/") {
			return true
		}
	}
	return false
}

func (sm *Manager) SetAnalyticsFactory(factory StreamAnalyticsFactory) {
	if factory == nil {
		factory = &NoopStreamAnalyticsFactory{}
	}
	sm.analyticsFactoryMu.Lock()
	sm.analyticsFactory = factory
	sm.analyticsFactoryMu.Unlock()
}

func (sm *Manager) getAnalyticsFactory() StreamAnalyticsFactory {
	sm.analyticsFactoryMu.RLock()
	factory := sm.analyticsFactory
	sm.analyticsFactoryMu.RUnlock()
	if factory == nil {
		return &NoopStreamAnalyticsFactory{}
	}
	return factory
}
