package streaming

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"

	_ "github.com/benthosdev/benthos/v4/public/components/all"
	"github.com/benthosdev/benthos/v4/public/service"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	_ "github.com/TykTechnologies/tyk/internal/portal"
)

type StreamManager struct {
	streamConfigs       map[string]string
	streams             map[string]*service.Stream
	streamConsumerGroup map[string]string
	mu                  sync.Mutex
	subscriberChans     map[string][]chan []byte
	redis               redis.UniversalClient
	log                 *logrus.Logger
}

func NewStreamManager(rcon redis.UniversalClient) *StreamManager {
	logger := logrus.New()
	logger.Out = log.Writer()
	logger.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}
	logger.Level = logrus.DebugLevel

	return &StreamManager{
		streamConfigs:       make(map[string]string),
		streams:             make(map[string]*service.Stream),
		subscriberChans:     make(map[string][]chan []byte),
		streamConsumerGroup: make(map[string]string),
		redis:               rcon,
		log:                 logger,
	}
}

func (sm *StreamManager) SetLogger(logger *logrus.Logger) {
	if logger != nil {
		sm.log = logger
	}
}

func (sm *StreamManager) AddStream(streamID string, config map[string]interface{}, mux service.HTTPMultiplexer) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	pc := make([]uintptr, 10) // at most 10 entries
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])

	sm.log.Println("Adding stream:")
	for {
		frame, more := frames.Next()
		sm.log.Printf("- %s\n\t%s:%d", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}

	configPayload, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	if _, exists := sm.streams[streamID]; exists {
		sm.log.Printf("stream %s already exists, removing it first", streamID)

		sm.mu.Unlock()
		if err := sm.RemoveStream(streamID); err != nil {
			return err
		}
		sm.mu.Lock()
	}

	builder := service.NewStreamBuilder()

	configPayload, err = sm.addMetadata(configPayload, "stream_id", streamID)
	if err != nil {
		return err
	}

	configPayload, consumerGroup, err := sm.readConsumerGroup(configPayload)
	if err != nil {
		return err
	}

	err = builder.SetYAML(string(configPayload))
	if err != nil {
		return err
	}

	if mux != nil {
		builder.SetHTTPMux(mux)
	}

	if sm.redis != nil {
		builder.AddConsumerFunc(sm.ConsumerHook(streamID))
	}

	stream, err := builder.Build()
	if err != nil {
		return err
	}

	sm.streamConfigs[streamID] = string(configPayload)
	sm.streams[streamID] = stream
	sm.streamConsumerGroup[streamID] = consumerGroup

	go func() {
		if err := stream.Run(context.Background()); err != nil {
			sm.log.Printf("stream %s encountered an error: %v", streamID, err)
		}
	}()

	return nil
}

func (sm *StreamManager) ConsumerGroup(streamID string) (string, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	consumerGroup, exists := sm.streamConsumerGroup[streamID]
	return consumerGroup, exists
}

func (sm *StreamManager) ConsumerHook(streamID string) func(ctx context.Context, msg *service.Message) error {
	return func(ctx context.Context, msg *service.Message) error {
		sm.mu.Lock()
		_, ok := sm.subscriberChans[streamID]
		sm.mu.Unlock()

		if ok {
			b, err := msg.AsBytes()
			if err != nil {
				sm.log.Println("failed to convert message to bytes:", err)
				return err
			}

			err = sm.redis.XAdd(context.Background(), &redis.XAddArgs{
				Stream: streamID,
				Values: map[string]interface{}{"message": b},
			}).Err()
			if err != nil {
				sm.log.Printf("error relaying message to Redis stream %s: %v", streamID, err)
			}
		}
		return nil
	}
}

func (sm *StreamManager) Subscribe(streamID string, consumerGroup string, bufferSize int) (chan []byte, context.CancelFunc, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.log.Printf("Subscribing to stream %s with consumer group %s", streamID, consumerGroup)

	// Check if the stream exists
	if _, exists := sm.streams[streamID]; !exists {
		return nil, nil, fmt.Errorf("stream not found: %s", streamID)
	}

	// Check if the consumer group exists, if not create it
	err := sm.redis.XGroupCreateMkStream(context.Background(), streamID, consumerGroup, "$").Err()
	if err != nil && err != redis.Nil {
		sm.log.Printf("Error while creating consumer group %s for stream %s: %v", consumerGroup, streamID, err)
	}

	// Create and add the subscriber channel
	subChan := make(chan []byte, bufferSize)
	sm.subscriberChans[streamID] = append(sm.subscriberChans[streamID], subChan)
	ctxWithCancel, cancel := context.WithCancel(context.Background())

	go func(ctx context.Context) {
		for {
			msgs, err := sm.redis.XReadGroup(context.Background(), &redis.XReadGroupArgs{
				Group:    consumerGroup,
				Consumer: "consumer-" + streamID,
				Streams:  []string{streamID, ">"},
				Count:    10,
				Block:    0,
			}).Result()

			select {
			case <-ctx.Done():
				sm.log.Println("context cancelled, stopping subscriber")
				close(subChan)
				return
			default:
			}

			if err == redis.Nil {
				return // Exit the loop if the stream is empty or does not exist
			}
			if err != nil {
				sm.log.Printf("error reading from stream %s: %v", streamID, err)
				continue
			}

			for _, msg := range msgs {
				for _, xmsg := range msg.Messages {
					message, ok := xmsg.Values["message"].([]byte)
					if !ok {
						if strMsg, ok := xmsg.Values["message"].(string); ok {
							message = []byte(strMsg)
						} else {
							sm.log.Println("Message is neither []byte nor string")
							continue
						}
					}
					select {
					case <-ctx.Done():
						sm.log.Println("context cancelled with messages left, stopping send")
						close(subChan)
						return
					case subChan <- message:
						sm.log.Println("message sent to subscriber")
					default:
						sm.log.Println("Dropping message for a full subscriber queue")
					}
				}
			}
		}
	}(ctxWithCancel)

	return subChan, cancel, nil
}

func (sm *StreamManager) Unsubscribe(streamID string, consumerGroup string, unsubChan chan []byte, cancel context.CancelFunc) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	subs, ok := sm.subscriberChans[streamID]
	if !ok {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	for i, sub := range subs {
		if sub == unsubChan {
			cancel()
			subs = append(subs[:i], subs[i+1:]...)
			sm.subscriberChans[streamID] = subs
			return nil
		}
	}

	return fmt.Errorf("subscriber channel not found for stream: %s", streamID)
}

func (sm *StreamManager) RemoveStream(streamID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.log.Printf("stopping stream %s", streamID)

	stream, exists := sm.streams[streamID]
	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	go func() {
		if err := stream.Stop(context.Background()); err != nil {
			sm.log.Printf("error stopping stream %s: %v", streamID, err)
		}

		sm.log.Printf("stream %s stopped", streamID)
	}()

	// Close all subscriber channels for the stream
	if subs, ok := sm.subscriberChans[streamID]; ok {
		for _, sub := range subs {
			close(sub)
		}
	}

	delete(sm.streamConfigs, streamID)
	delete(sm.streams, streamID)
	delete(sm.subscriberChans, streamID)
	delete(sm.streamConsumerGroup, streamID)

	return nil
}

func (sm *StreamManager) Streams() map[string]string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return sm.streamConfigs
}

func (sm *StreamManager) Reset() error {
	for streamID := range sm.streams {
		if err := sm.RemoveStream(streamID); err != nil {
			sm.log.Printf("error removing stream %s: %v", streamID, err)
		}
	}

	return nil
}

func (sm *StreamManager) addMetadata(configPayload []byte, key, value string) ([]byte, error) {
	var parsedConfig map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &parsedConfig); err != nil {
		return nil, err
	}

	newProcessor := map[interface{}]interface{}{
		"mapping": fmt.Sprintf("meta %s = \"%s\"", key, value),
	}

	for key, value := range parsedConfig {
		if key == "input" {
			inputMap, ok := value.(map[interface{}]interface{})
			if !ok {
				sm.log.Printf("expected map[interface{}]interface{}, got %T", value)
				continue
			}

			if processors, found := inputMap["processors"]; found {
				if procSlice, ok := processors.([]map[interface{}]interface{}); ok {
					inputMap["processors"] = append([]map[interface{}]interface{}{newProcessor}, procSlice...)
				}
			} else {
				inputMap["processors"] = []map[interface{}]interface{}{newProcessor}
			}
			break
		}
	}

	configPayload, err := yaml.Marshal(parsedConfig)
	if err != nil {
		return nil, err
	}
	return configPayload, nil
}

func (sm *StreamManager) readConsumerGroup(configPayload []byte) ([]byte, string, error) {
	var parsedConfig map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &parsedConfig); err != nil {
		return nil, "", err
	}

	var consumerGroup string
	handleHttpServer := func(httpServerMap map[interface{}]interface{}) {
		if cg, found := httpServerMap["consumer_group"]; found {
			consumerGroup, _ = cg.(string)
			delete(httpServerMap, "consumer_group")
		}
	}

	if output, found := parsedConfig["output"]; found {
		switch outputTyped := output.(type) {
		case map[interface{}]interface{}:
			if httpServer, found := outputTyped["http_server"]; found {
				httpServerMap, ok := httpServer.(map[interface{}]interface{})
				if ok {
					handleHttpServer(httpServerMap)
				}
			}
		case []interface{}:
			for _, out := range outputTyped {
				outMap, ok := out.(map[interface{}]interface{})
				if ok {
					if httpServer, found := outMap["http_server"]; found {
						httpServerMap, ok := httpServer.(map[interface{}]interface{})
						if ok {
							handleHttpServer(httpServerMap)
						}
					}
				}
			}
		}
	}

	// Handle nested http_server within broker
	if broker, found := parsedConfig["output"].(map[interface{}]interface{})["broker"]; found {
		brokerMap, ok := broker.(map[interface{}]interface{})
		if ok {
			if outputs, found := brokerMap["outputs"]; found {
				outputsSlice, ok := outputs.([]interface{})
				if ok {
					for _, output := range outputsSlice {
						outputMap, ok := output.(map[interface{}]interface{})
						if ok {
							if httpServer, found := outputMap["http_server"]; found {
								httpServerMap, ok := httpServer.(map[interface{}]interface{})
								if ok {
									handleHttpServer(httpServerMap)
								}
							}
						}
					}
				}
			}
		}
	}

	// Re-marshal the modified configuration without the consumer_group in http_server
	newConfigPayload, err := yaml.Marshal(parsedConfig)
	if err != nil {
		return nil, "", err
	}

	sm.log.Printf("New config: %s", string(newConfigPayload))

	return newConfigPayload, consumerGroup, nil
}

func (sm *StreamManager) GetHTTPPaths(component, streamID string) (map[string]string, error) {
	config, exists := sm.streamConfigs[streamID]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	var parsedConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(config), &parsedConfig); err != nil {
		return nil, err
	}

	defaultPaths := map[string]map[string]string{
		"output": {
			"path":        "/get",
			"stream_path": "/get/stream",
			"ws_path":     "/get/ws",
		},
		"input": {
			"path":    "/post",
			"ws_path": "/post/ws",
		},
	}

	paths := defaultPaths[component]

	if compConfig, found := parsedConfig[component]; found {
		compMap, ok := compConfig.(map[interface{}]interface{})
		if !ok {
			return paths, nil
		}

		if http, found := compMap["http_server"]; found {
			httpMap, ok := http.(map[interface{}]interface{})
			if !ok {
				return paths, nil
			}

			for key := range paths {
				if p, found := httpMap[key]; found && p != "" {
					paths[key], _ = p.(string)
				}
			}
		}
	}

	return paths, nil
}
