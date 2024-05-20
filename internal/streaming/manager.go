package streaming

import (
	// Import all standard Benthos components
	"context"
	"fmt"
	"log"
	"sync"

	_ "github.com/benthosdev/benthos/v4/public/components/all"
	"github.com/benthosdev/benthos/v4/public/service"
	"gopkg.in/yaml.v2"
)

type StreamManager struct {
	streamConfigs map[string]string
	streams       map[string]*service.Stream
	mu            sync.Mutex
}

func NewStreamManager() *StreamManager {
	return &StreamManager{
		streamConfigs: make(map[string]string),
		streams:       make(map[string]*service.Stream),
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

	// builder.AddProcessorYAML(`type: metadata
	//  metadata:
	//    operator: set
	//    key: "stream_id"
	//    value: "asdasd"`)

	err = builder.SetYAML(string(configPayload))
	if err != nil {
		return err
	}

	if mux != nil {
		builder.SetHTTPMux(mux)
	}

	// builder.AddConsumerFunc(func(ctx context.Context, msg *service.Message) error {
	// 	b, _ := msg.AsBytes()
	// 	log.Println("received message", string(b))
	// 	msg.MetaSetMut("stream-id", streamID)
	// 	return nil
	// })

	stream, err := builder.Build()
	if err != nil {
		return err
	}

	sm.streamConfigs[streamID] = string(configPayload)
	sm.streams[streamID] = stream

	go func() {
		if err := stream.Run(context.Background()); err != nil {
			log.Printf("stream %s encountered an error: %v", streamID, err)
		}
	}()

	return nil
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

	delete(sm.streamConfigs, streamID)
	delete(sm.streams, streamID)

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
