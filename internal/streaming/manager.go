package streaming

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	_ "github.com/TykTechnologies/benthos/v4/public/components/all"
	"github.com/TykTechnologies/benthos/v4/public/service"

	_ "github.com/TykTechnologies/tyk/internal/portal"
)

type Stream struct {
	allowedUnsafe []string
	streamConfig  string
	stream        *service.Stream
	log           *logrus.Logger
}

func NewStream(allowUnsafe []string) *Stream {
	logger := logrus.New()
	logger.Out = log.Writer()
	logger.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}
	logger.Level = logrus.DebugLevel

	if len(allowUnsafe) > 0 {
		logger.Warnf("Allowing unsafe components: %v", allowUnsafe)
	}

	return &Stream{
		log:           logger,
		allowedUnsafe: allowUnsafe,
	}
}

func (s *Stream) SetLogger(logger *logrus.Logger) {
	if logger != nil {
		s.log = logger
	}
}

func (s *Stream) Start(config map[string]interface{}, mux service.HTTPMultiplexer) error {
	s.log.Debugf("Starting stream")

	configPayload, err := yaml.Marshal(config)
	if err != nil {
		s.log.Errorf("Failed to marshal config: %v", err)
		return err
	}

	configPayload = s.removeUnsafe(configPayload)
	configPayload, err = s.removeConsumerGroup(configPayload)
	if err != nil {
		s.log.Errorf("Failed to remove consumer_group: %v", err)
		return err
	}

	s.log.Debugf("Building new stream")
	builder := service.NewStreamBuilder()

	err = builder.SetYAML(string(configPayload))
	if err != nil {
		s.log.Errorf("Failed to set YAML: %v", err)
		return err
	}

	if mux != nil {
		builder.SetHTTPMux(mux)
	}

	stream, err := builder.Build()
	if err != nil {
		s.log.Errorf("Failed to build stream: %v", err)
		return err
	}

	s.streamConfig = string(configPayload)
	s.stream = stream

	s.log.Debugf("Stream built successfully, starting it")

	go func() {
		s.log.Infof("Starting stream")

		if err := stream.Run(context.Background()); err != nil {
			s.log.Errorf("Stream encountered an error: %v", err)
		}
	}()

	s.log.Debugf("Stream started successfully")
	return nil
}

func (s *Stream) Stop() error {
	s.log.Printf("Stopping stream")

	if s.stream == nil {
		return fmt.Errorf("no active stream to stop")
	}

	go func() {
		if err := s.stream.Stop(context.Background()); err != nil {
			s.log.Printf("Error stopping stream: %v", err)
		}

		s.log.Printf("Stream stopped")
	}()

	s.streamConfig = ""
	s.stream = nil

	return nil
}

func (s *Stream) GetConfig() string {
	return s.streamConfig
}

func (s *Stream) Reset() error {
	return s.Stop()
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

func (sm *StreamManager) GetHTTPPaths(component, streamID string) (map[string]string, error) {
	configValue, exists := sm.streamConfigs.Load(streamID)
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	config, ok := configValue.(string)
	if !ok {
		return nil, fmt.Errorf("invalid config type for stream: %s", streamID)
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

var unsafeComponents = []string{
	// Inputs
	"csv", "dynamic", "file", "inproc", "socket", "socket_server", "stdin", "subprocess",

	// Processors
	"command", "subprocess", "wasm",

	// Outputs
	"file", "inproc", "socket",

	// Caches
	"file",
}

func (sm *StreamManager) removeUnsafe(yamlBytes []byte) []byte {
	filteredUnsafeComponents := []string{}

	for _, component := range unsafeComponents {
		allowed := false
		for _, allowedComponent := range sm.allowedUnsafe {
			if component == allowedComponent {
				allowed = true
				break
			}
		}
		if !allowed {
			filteredUnsafeComponents = append(filteredUnsafeComponents, component)
		}
	}

	yamlString := string(yamlBytes)
	for _, key := range filteredUnsafeComponents {
		if strings.Contains(yamlString, key+":") {
			// Use regexp to match the whole block of the given key
			re := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*%s:\s*(.*\r?\n?)(\s+.*(?:\r?\n?|\z))*`, regexp.QuoteMeta(key)))
			// Remove matched parts
			yamlString = re.ReplaceAllString(yamlString, "")

			sm.log.Info("Removed unsafe component: ", key)
		}
	}
	return []byte(yamlString)
}

func (sm *StreamManager) removeConsumerGroup(configPayload []byte) ([]byte, error) {
	var parsedConfig map[interface{}]interface{}
	if err := yaml.Unmarshal(configPayload, &parsedConfig); err != nil {
		return nil, err
	}

	removeFromMap := func(m map[interface{}]interface{}) {
		if httpServer, ok := m["http_server"].(map[interface{}]interface{}); ok {
			delete(httpServer, "consumer_group")
		}
	}

	if output, ok := parsedConfig["output"].(map[interface{}]interface{}); ok {
		removeFromMap(output)
	}

	if broker, ok := parsedConfig["output"].(map[interface{}]interface{})["broker"].(map[interface{}]interface{}); ok {
		if outputs, ok := broker["outputs"].([]interface{}); ok {
			for _, output := range outputs {
				if outputMap, ok := output.(map[interface{}]interface{}); ok {
					removeFromMap(outputMap)
				}
			}
		}
	}

	newConfigPayload, err := yaml.Marshal(parsedConfig)
	if err != nil {
		return nil, err
	}

	return newConfigPayload, nil
}
