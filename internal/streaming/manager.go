package streaming

import (
	// Import all standard Benthos components
	"context"
	"fmt"
	"log"
	"sync"

	_ "github.com/benthosdev/benthos/v4/public/components/all"
	"github.com/benthosdev/benthos/v4/public/service"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v2"
)

type StreamManager struct {
	streamConfigs       map[string]string
	streams             map[string]*service.Stream
	streamConsumerGroup map[string]string
	mu                  sync.Mutex
	subscriberChans     map[string][]chan []byte
	redis               redis.UniversalClient
}

func NewStreamManager(rcon redis.UniversalClient) *StreamManager {
	return &StreamManager{
		streamConfigs:       make(map[string]string),
		streams:             make(map[string]*service.Stream),
		subscriberChans:     make(map[string][]chan []byte),
		streamConsumerGroup: make(map[string]string),
		redis:               rcon,
	}
}

func (sm *StreamManager) AddStream(streamID string, config map[string]interface{}, mux service.HTTPMultiplexer) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	configPayload, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	if _, exists := sm.streams[streamID]; exists {
		log.Printf("stream %s already exists, removing it first", streamID)

		sm.mu.Unlock()
		if err := sm.RemoveStream(streamID); err != nil {
			return err
		}
		sm.mu.Lock()
	}

	builder := service.NewStreamBuilder()

	configPayload, err = addMetadata(configPayload, "stream_id", streamID)
	if err != nil {
		return err
	}

	configPayload, consumerGroup, err := readConsumerGroup(configPayload)
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
			log.Printf("stream %s encountered an error: %v", streamID, err)
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
		subs, ok := sm.subscriberChans[streamID]
		sm.mu.Unlock()

		if ok {
			b, err := msg.AsBytes()
			if err != nil {
				log.Println("failed to convert message to bytes:", err)
				return err
			}

			err = sm.redis.XAdd(context.Background(), &redis.XAddArgs{
				Stream: streamID,
				Values: map[string]interface{}{"message": b},
			}).Err()
			if err != nil {
				log.Printf("error relaying message to Redis stream %s: %v", streamID, err)
			}

			return nil

			log.Printf("fan out message to %d subscribers", len(subs))
			// Fan out the message to all subscribers
			for i, sub := range subs {
				select {
				case sub <- b:
				case <-ctx.Done():
					// Context cancelled, remove subscriber
					close(sub)
					subs = append(subs[:i], subs[i+1:]...)

					sm.mu.Lock()
					sm.subscriberChans[streamID] = subs
					sm.mu.Unlock()
				default:
					log.Println("Dropping message for a full subscriber queue")
				}
			}

			log.Println("message sent to all subscribers")
		}
		return nil
	}
}

func (sm *StreamManager) Subscribe(streamID string, consumerGroup string, bufferSize int) (chan []byte, context.CancelFunc, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if the stream exists
	if _, exists := sm.streams[streamID]; !exists {
		return nil, nil, fmt.Errorf("stream not found: %s", streamID)
	}

	// Check if the consumer group exists, if not create it
	err := sm.redis.XGroupCreateMkStream(context.Background(), streamID, consumerGroup, "$").Err()
	if err != nil && err != redis.Nil {
		return nil, nil, fmt.Errorf("error creating consumer group %s for stream %s: %v", consumerGroup, streamID, err)
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
				log.Println("context cancelled, stopping subscriber")
				close(subChan)
				return
			default:
			}

			if err == redis.Nil {
				return // Exit the loop if the stream is empty or does not exist
			}
			if err != nil {
				log.Printf("error reading from stream %s: %v", streamID, err)
				continue
			}

			for _, msg := range msgs {
				for _, xmsg := range msg.Messages {
					message, ok := xmsg.Values["message"].([]byte)
					if !ok {
						if strMsg, ok := xmsg.Values["message"].(string); ok {
							message = []byte(strMsg)
						} else {
							log.Println("Message is neither []byte nor string")
							continue
						}
					}
					select {
					case <-ctx.Done():
						log.Println("context cancelled with messages left, stopping send")
						close(subChan)
						return
					case subChan <- message:
						log.Println("message sent to subscriber")
					default:
						log.Println("Dropping message for a full subscriber queue")
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

	stream, exists := sm.streams[streamID]
	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	go func() {
		if err := stream.Stop(context.Background()); err != nil {
			log.Printf("error stopping stream %s: %v", streamID, err)
		}

		log.Printf("stream %s stopped", streamID)
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
			log.Printf("error removing stream %s: %v", streamID, err)
		}
	}

	return nil
}

func addMetadata(configPayload []byte, key, value string) ([]byte, error) {
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
				log.Printf("expected map[interface{}]interface{}, got %T", value)
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

func readConsumerGroup(configPayload []byte) ([]byte, string, error) {
	var parsedConfig map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &parsedConfig); err != nil {
		return nil, "", err
	}

	var consumerGroup string
	if output, found := parsedConfig["output"]; found {
		outputMap, ok := output.(map[interface{}]interface{})
		if !ok {
			return configPayload, "", nil // Return original payload and no error if parsing fails
		}
		if httpServer, found := outputMap["http_server"]; found {
			httpServerMap, ok := httpServer.(map[interface{}]interface{})
			if !ok {
				return configPayload, "", nil // Return original payload and no error if parsing fails
			}
			if cg, found := httpServerMap["consumer_group"]; found {
				consumerGroup, _ = cg.(string)
				delete(httpServerMap, "consumer_group")
			}
		}
	}

	// Re-marshal the modified configuration without the consumer_group in http_server
	newConfigPayload, err := yaml.Marshal(parsedConfig)
	if err != nil {
		return nil, "", err
	}

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
