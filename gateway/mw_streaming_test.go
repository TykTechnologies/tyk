//go:build ee || dev

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	natscon "github.com/testcontainers/testcontainers-go/modules/nats"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v2"

	"github.com/IBM/sarama"
	"github.com/testcontainers/testcontainers-go/modules/kafka"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/test"
)

func TestGetHTTPPaths(t *testing.T) {
	testCases := []struct {
		name       string
		configYaml string
		expected   []string
	}{
		{
			name: "should get paths",
			configYaml: `
input:
  http_server:
    path: /post
  label: example_generator_input

output:
  http_server:
    ws_path: /subscribe
    stream_path: /stream
  label: example_generator_output
`,
			expected: []string{"/subscribe", "/post", "/stream", "/post/ws", "/get/stream"},
		}, {
			name: "should get paths with broker",
			configYaml: `
input:
  broker:
    inputs:
      - http_server:
          path: /post

output:
  http_server:
    ws_path: /subscribe
    stream_path: /stream
  label: example_generator_output

`,
			expected: []string{"/subscribe", "/post", "/stream", "/post/ws", "/get/stream"},
		},
		{
			name: "no http_server",
			configYaml: `
input:
  kafka:
    consumer_group: test

output:
  test:
    field: value
`,
			expected: []string{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := yamlConfigToMap(tc.configYaml)
			require.NoError(t, err)
			httpPaths := streams.GetHTTPPaths(config)
			assert.ElementsMatch(t, tc.expected, httpPaths)
		})
	}
}

// ConvertYAMLToJSON converts a YAML byte slice to a JSON byte slice
func ConvertYAMLToJSON(yamlData []byte) ([]byte, error) {
	var rawData interface{}
	if err := yaml.Unmarshal(yamlData, &rawData); err != nil {
		return nil, fmt.Errorf("error unmarshaling YAML: %w", err)
	}

	// Convert map[interface{}]interface{} to map[string]interface{}
	data := convertToStringKeyMap(rawData)

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling to JSON: %w", err)
	}

	return jsonData, nil
}

// convertToStringKeyMap recursively converts map[interface{}]interface{} to map[string]interface{}
func convertToStringKeyMap(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, v := range x {
			m[fmt.Sprintf("%v", k)] = convertToStringKeyMap(v)
		}
		return m
	case []interface{}:
		for i, v := range x {
			x[i] = convertToStringKeyMap(v)
		}
	}
	return i
}

const bentoNatsTemplate = `
streams:
  test:
    input:
      nats:
        auto_replay_nacks: true
        subject: "%s"
        urls: ["%s"]
    output:
      http_server:
        path: /get
        ws_path: /get/ws
    logger:
      level: DEBUG
      format: logfmt
      add_timestamp: false
`
const bentoHTTPServerTemplate = `
streams:
  test:
    input:
      http_server:
        path: /post
        timeout: 1s
    output:
      http_server:
        ws_path: /subscribe
`

func TestStreamingAPISingleClient(t *testing.T) {
	ctx := context.Background()

	natsContainer, err := natscon.Run(
		ctx,
		"nats:2.9",
		testcontainers.WithWaitStrategy(wait.ForAll(
			wait.ForLog("Server is ready"),
			wait.ForListeningPort("4222/tcp"),
		).WithDeadline(30*time.Second)))
	require.NoError(t, err)

	//skip if is dynamic, does not work

	configSubject := "test"

	connectionStr, err := natsContainer.ConnectionString(ctx)
	assert.NoError(t, err)
	streamConfig := fmt.Sprintf(bentoNatsTemplate, configSubject, connectionStr)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	t.Cleanup(func() {
		ts.Close()
	})
	//t.Cleanup(func() { ts.Close() })
	apiName := "test-api"
	if err = setUpStreamAPI(ts, apiName, streamConfig); err != nil {
		t.Fatal(err)
	}

	const totalMessages = 3

	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/get/ws", apiName)

	println("wsURL:", wsURL)

	wsConn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err, "failed to connect to ws server")
	t.Cleanup(func() {
		if err = wsConn.Close(); err != nil {
			t.Logf("failed to close ws connection: %v", err)
		}
	})

	nc, err := nats.Connect(connectionStr)
	require.NoError(t, err, "error connecting to nats server")
	t.Cleanup(func() {
		nc.Close()
	})
	subject := "test"
	for i := 0; i < totalMessages; i++ {
		require.NoError(t, nc.Publish(subject, []byte(fmt.Sprintf("Hello %d", i))), "failed to publish message to subject")
	}

	err = wsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	require.NoError(t, err, "error setting read deadline")

	for i := 0; i < totalMessages; i++ {
		_, p, err := wsConn.ReadMessage()
		require.NoError(t, err, "error reading message")
		assert.Equal(t, fmt.Sprintf("Hello %d", i), string(p), "message not equal")
	}
}
func TestStreamingAPIMultipleClients(t *testing.T) {
	ctx := context.Background()

	natsContainer, err := natscon.Run(
		ctx,
		"nats:2.9",
		testcontainers.WithWaitStrategy(wait.ForAll(
			wait.ForLog("Server is ready"),
		).WithDeadline(30*time.Second)))
	require.NoError(t, err)

	connectionStr, err := natsContainer.ConnectionString(ctx)
	require.NoError(t, err)

	streamConfig := fmt.Sprintf(bentoNatsTemplate, "test", connectionStr)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	t.Cleanup(func() {
		ts.Close()
	})
	apiName := "test-api"

	if err = setUpStreamAPI(ts, apiName, streamConfig); err != nil {
		t.Fatal(err)
	}

	const (
		totalClients  = 3
		totalMessages = 3
	)
	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/get/ws", apiName)

	// Create multiple WebSocket connections
	var wsConns []*websocket.Conn
	for i := 0; i < totalClients; i++ {
		wsConn, _, err := dialer.Dial(wsURL, nil)
		require.NoError(t, err, fmt.Sprintf("failed to connect to ws server for client %d", i))
		wsConns = append(wsConns, wsConn)
		t.Cleanup(func() {
			if err := wsConn.Close(); err != nil {
				t.Logf("failed to close ws connection: %v", err)
			}
		})
	}

	// Connect to NATS and publish messages
	nc, err := nats.Connect(connectionStr)
	require.NoError(t, err, "error connecting to nats server")
	t.Cleanup(func() {
		nc.Close()
	})

	subject := "test"
	messages := make(map[string]struct{})
	for i := 0; i < totalMessages; i++ {
		message := fmt.Sprintf("Hello %d", i)
		messages[message] = struct{}{}
		require.NoError(t, nc.Publish(subject, []byte(message)), "failed to publish message to subject")
	}

	// Read messages from all subscribers
	// Messages are distributed in a round-robin fashion, count the number of messages and check the messages individually.
	var readMessages int
	for readMessages < totalMessages {
		for clientID, wsConn := range wsConns {
			// We need to stop waiting for a message if the subscriber is consumed all of its received messages.
			err = wsConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			require.NoError(t, err, fmt.Sprintf("error setting read deadline for client %d", clientID))

			_, data, err := wsConn.ReadMessage()
			if os.IsTimeout(err) {
				continue
			}
			require.NoError(t, err, fmt.Sprintf("error reading message for client %d", clientID))

			message := string(data)
			_, ok := messages[message]
			require.True(t, ok, fmt.Sprintf("message is unknown or consumed before %s", message))
			delete(messages, message)
			readMessages++
		}
	}
	// Consumed all messages
	require.Empty(t, messages)
}

func setUpStreamAPI(ts *Test, apiName string, streamConfig string) error {
	oasAPI, err := setupOASForStreamAPI(streamConfig)
	if err != nil {
		return err
	}
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = fmt.Sprintf("/%s", apiName)
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
		spec.OAS.Fill(*spec.APIDefinition)
	})

	return nil
}

func setupOASForStreamAPI(streamingConfig string) (oas.OAS, error) {
	parsedStreamingConfig, err := yamlConfigToMap(streamingConfig)
	if err != nil {
		return oas.OAS{}, err
	}

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "oas doc",
				Version: "1",
			},
			Paths: make(openapi3.Paths),
		},
	}

	oasAPI.Extensions = map[string]interface{}{
		streams.ExtensionTykStreaming: parsedStreamingConfig,
	}

	return oasAPI, nil
}

func yamlConfigToMap(streamingConfig string) (map[string]interface{}, error) {
	streamingConfigJSON, err := ConvertYAMLToJSON([]byte(streamingConfig))
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	var parsedStreamingConfig map[string]interface{}
	if err := json.Unmarshal(streamingConfigJSON, &parsedStreamingConfig); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return parsedStreamingConfig, nil
}

func TestAsyncAPI(t *testing.T) {
	t.SkipNow()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = true
	})

	// Check that standard API works
	_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Method: http.MethodGet, Path: "/test"})

	defer ts.Close()

	tempFile, err := os.CreateTemp("", "test-output-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	require.NoError(t, tempFile.Close())
	t.Cleanup(func() {
		if err = os.Remove(tempFile.Name()); err != nil {
			t.Logf("Failed to remove temporary file: %v", err)
		}
	})
	tempFilePath := tempFile.Name()

	streamingConfig := `
streams:
  test:
    input:
      label: "in"
      generate:
        count: 3
        interval: ""
        mapping: root = "hello world"

    output:
      label: "out"
      file:
        path: "%s"
        codec: lines`

	streamingConfig = fmt.Sprintf(streamingConfig, tempFilePath)

	streamingConfigJSON, err := ConvertYAMLToJSON([]byte(streamingConfig))
	if err != nil {
		t.Fatalf("Failed to convert YAML to JSON: %v", err)
	}

	var parsedStreamingConfig map[string]interface{}
	if err = json.Unmarshal(streamingConfigJSON, &parsedStreamingConfig); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "oas doc",
				Version: "1",
			},
			Paths: make(openapi3.Paths),
		},
	}

	oasAPI.Extensions = map[string]interface{}{
		streams.ExtensionTykStreaming: parsedStreamingConfig,
		// oas.ExtensionTykAPIGateway: tykExtension,
	}

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = true
	}, func(spec *APISpec) {
		spec.SetDisabledFlags()
		spec.APIID = "base-api-id"
		spec.VersionDefinition.Enabled = false
		spec.VersionDefinition.Key = ""
		spec.VersionDefinition.Location = ""

		spec.IsOAS = true
		spec.OAS = oasAPI
		spec.OAS.Fill(*spec.APIDefinition)
	})

	// Check that standard API still works
	_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Method: http.MethodGet, Path: "/test"})

	if streams.GlobalStreamCounter.Load() != 1 {
		t.Fatalf("Expected 1 stream, got %d", streams.GlobalStreamCounter.Load())
	}

	time.Sleep(500 * time.Millisecond)

	content, err := os.ReadFile(tempFilePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	lines := strings.Split(string(content), "\n")

	// Adjust for the trailing new line which results in an extra empty element in the slice
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines, got %d", len(lines))
	}

	for _, line := range lines {
		if line != "hello world" {
			t.Fatalf("Expected 'hello world', got '%s'", line)
		}
	}
}

func TestAsyncAPIHttp(t *testing.T) {
	var tests = []struct {
		name          string
		consumerGroup string
		tenantID      string
		isDynamic     bool
	}{
		{"StaticGroup", "static-group", "default", false},
		{"DynamicGroup", "$tyk_context.request_id", "dynamic", true},
	}
	ctx := context.Background()
	kafkaContainer, err := kafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	if err != nil {
		t.Fatalf("Failed to start Kafka container: %v", err)
	}
	t.Cleanup(func() {
		if err = kafkaContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Kafka container: %v", err)
		}
	})

	brokers, err := kafkaContainer.Brokers(ctx)
	if err != nil {
		t.Fatalf("Failed to get Kafka brokers: %v", err)
	}

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	defer ts.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apiName := setupStreamingAPI(t, ts, tc.consumerGroup, tc.tenantID, brokers[0])
			testAsyncAPIHttp(t, ts, tc.isDynamic, tc.tenantID, apiName, brokers[0])
		})
	}
}

func setupStreamingAPI(t *testing.T, ts *Test, consumerGroup string, tenantID string, kafkaHost string) string {
	t.Helper()
	t.Logf("Setting up streaming API for tenant: %s with consumer group: %s", tenantID, consumerGroup)

	apiName := fmt.Sprintf("streaming-api-%s", tenantID)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = fmt.Sprintf("/%s", apiName)
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = setupOASForStreamingAPI(t, consumerGroup, kafkaHost)
		spec.OAS.Fill(*spec.APIDefinition)
		spec.EnableContextVars = true
	})

	return apiName
}

func setupOASForStreamingAPI(t *testing.T, consumerGroup string, kafkaHost string) oas.OAS {
	t.Helper()
	streamingConfig := fmt.Sprintf(`
streams:
 test:
  input:
   kafka:
    addresses: ["%s"]
    topics: ["test"]
    consumer_group: "%s"

  output:
   http_server:
    path: /get
    ws_path: /get/ws`, kafkaHost, consumerGroup)

	streamingConfigJSON, err := ConvertYAMLToJSON([]byte(streamingConfig))
	if err != nil {
		t.Fatalf("Failed to convert YAML to JSON: %v", err)
	}

	var parsedStreamingConfig map[string]interface{}
	if err := json.Unmarshal(streamingConfigJSON, &parsedStreamingConfig); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "oas doc",
				Version: "1",
			},
			Paths: make(openapi3.Paths),
		},
	}

	oasAPI.Extensions = map[string]interface{}{
		streams.ExtensionTykStreaming: parsedStreamingConfig,
	}

	return oasAPI
}

func testAsyncAPIHttp(t *testing.T, ts *Test, isDynamic bool, tenantID string, apiName string, kafkaHost string) {
	t.Helper()
	const messageToSend = "hello websocket"
	const numMessages = 2
	const numClients = 2

	streamCount := streams.GlobalStreamCounter.Load()
	t.Logf("Stream count for tenant %s: %d", tenantID, streamCount)

	// Create WebSocket clients
	wsClients := make([]*websocket.Conn, numClients)
	for i := 0; i < numClients; i++ {
		dialer := websocket.Dialer{
			HandshakeTimeout: 5 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		}
		wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/get/ws", apiName)
		wsConn, resp, err := dialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("Failed to connect to WebSocket %d: %v\nResponse: %+v", i, err, resp)
		}
		t.Cleanup(func() {
			if err := wsConn.Close(); err != nil {
				t.Logf("Failed to close WebSocket %d: %v", i, err)
			}
		})
		wsClients[i] = wsConn
		t.Logf("Successfully connected to WebSocket %d", i)
	}

	// Send messages to Kafka
	saramaCfg := sarama.NewConfig()
	saramaCfg.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer([]string{kafkaHost}, saramaCfg)
	if err != nil {
		t.Fatalf("Failed to create Kafka producer: %v", err)
	}
	defer func() {
		if err = producer.Close(); err != nil {
			t.Logf("Failed to close Kafka producer: %v", err)
		}
	}()

	for i := 0; i < numMessages; i++ {
		msg := &sarama.ProducerMessage{
			Topic: "test",
			Value: sarama.StringEncoder(fmt.Sprintf("%s %d", messageToSend, i+1)),
		}

		t.Logf("Sending message to Kafka topic 'test': %s", msg.Value)
		partition, offset, err := producer.SendMessage(msg)
		if err != nil {
			t.Fatalf("Failed to send message to Kafka: %v", err)
		}
		t.Logf("Message sent to partition %d at offset %d", partition, offset)
	}

	expectedTotalMessages := numMessages
	if isDynamic {
		expectedTotalMessages *= numClients
	}

	messagesReceived := 0
	overallTimeout := time.After(20 * time.Second)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-overallTimeout:
				t.Log("Overall timeout reached while waiting for messages")
				done <- true
				return
			default:
				for i, wsConn := range wsClients {
					if err = wsConn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
						t.Error(err)
					}
					_, p, err := wsConn.ReadMessage()
					if err != nil {
						if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
							t.Logf("Unexpected error reading from WebSocket %d: %v", i+1, err)
						}
					} else {
						receivedMessage := string(p)
						t.Logf("Received message from WebSocket %d: %s", i+1, receivedMessage)
						if strings.HasPrefix(receivedMessage, messageToSend) {
							messagesReceived++
							t.Logf("Message from WebSocket %d matches sent message", i+1)
						}
					}
				}

				if messagesReceived >= expectedTotalMessages {
					t.Logf("Received all expected messages (%d)", messagesReceived)
					done <- true
					return
				}
			}
		}
	}()

	<-done

	t.Logf("Final message count: %d out of %d expected for tenant %s", messagesReceived, expectedTotalMessages, tenantID)
	if messagesReceived != expectedTotalMessages {
		t.Errorf("Expected %d messages, but received %d for tenant %s", expectedTotalMessages, messagesReceived, tenantID)
	} else {
		t.Logf("Successfully received %d messages as expected for tenant %s", messagesReceived, tenantID)
	}

	t.Log("Test completed, closing WebSocket connections")
}

func waitForAPIToBeLoaded(ts *Test) error {
	maxAttempts := 2
	for i := 0; i < maxAttempts; i++ {
		req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/streaming-api-default/metrics", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			if err = resp.Body.Close(); err != nil {
				log.Printf("Failed to close response body: %v", err)
			}
			return nil
		}
		if resp != nil {
			if err = resp.Body.Close(); err != nil {
				log.Printf("Failed to close response body: %v", err)
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("API failed to load after %d attempts", maxAttempts)
}

func TestWebSocketConnectionClosedOnAPIReload(t *testing.T) {
	t.Skip()
	ctx := context.Background()
	kafkaContainer, err := kafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	if err != nil {
		t.Fatalf("Failed to start Kafka container: %v", err)
	}
	t.Cleanup(func() {
		if err = kafkaContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Kafka container: %v", err)
		}
	})

	brokers, err := kafkaContainer.Brokers(ctx)
	if err != nil {
		t.Fatalf("Failed to get Kafka brokers: %v", err)
	}

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	defer ts.Close()

	apiName := setupStreamingAPI(t, ts, "test-group", "default", brokers[0])

	// Connect to WebSocket
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 1 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}
	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/get/ws", apiName)
	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	t.Cleanup(func() {
		if err = wsConn.Close(); err != nil {
			t.Logf("error closing WebSocket connection: %v", err)
		}
	})

	// Reload the API by rebuilding and loading it
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = fmt.Sprintf("/%s", apiName)
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = setupOASForStreamingAPI(t, "test-group", brokers[0])
	})

	// Wait for the API to be reloaded
	err = waitForAPIToBeLoaded(ts)
	if err != nil {
		t.Fatalf("API failed to reload: %v", err)
	}

	// Try to send a message, which should fail if the connection is closed
	err = wsConn.WriteMessage(websocket.TextMessage, []byte("test message"))
	if err == nil {
		t.Fatalf("Expected WebSocket connection to be closed, but write succeeded")
	}

	// Verify that the error indicates a closed connection
	if !websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
		t.Fatalf("Expected WebSocket to be closed with CloseGoingAway or CloseAbnormalClosure, got: %v", err)
	}

	t.Log("WebSocket connection was successfully closed on API reload")
}

func TestStreamingAPISingleClient_Input_HTTPServer(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	t.Cleanup(func() {
		ts.Close()
	})

	apiName := "test-api"
	if err := setUpStreamAPI(ts, apiName, bentoHTTPServerTemplate); err != nil {
		t.Fatal(err)
	}

	const totalMessages = 3

	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/subscribe", apiName)
	wsConn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err, "failed to connect to ws server")
	t.Cleanup(func() {
		if err = wsConn.Close(); err != nil {
			t.Logf("failed to close ws connection: %v", err)
		}
	})

	publishURL := fmt.Sprintf("%s/%s/post", ts.URL, apiName)
	for i := 0; i < totalMessages; i++ {
		data := []byte(fmt.Sprintf("{\"test\": \"message %d\"}", i))
		resp, err := http.Post(publishURL, "application/json", bytes.NewReader(data))
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	err = wsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	require.NoError(t, err, "error setting read deadline")

	for i := 0; i < totalMessages; i++ {
		println("reading message", i)
		_, p, err := wsConn.ReadMessage()
		require.NoError(t, err, "error reading message")
		assert.Equal(t, fmt.Sprintf("{\"test\": \"message %d\"}", i), string(p), "message not equal")
	}
}

func TestStreamingAPIMultipleClients_Input_HTTPServer(t *testing.T) {
	// Testing input http -> output http (3 output instances and 10 messages)
	// Messages are distributed in a round-robin fashion.

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	t.Cleanup(func() {
		ts.Close()
	})

	apiName := "test-api"
	if err := setUpStreamAPI(ts, apiName, bentoHTTPServerTemplate); err != nil {
		t.Fatal(err)
	}

	const (
		totalSubscribers = 3
		totalMessages    = 10
	)
	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/subscribe", apiName)

	// Create multiple WebSocket connections
	var wsConns []*websocket.Conn
	for i := 0; i < totalSubscribers; i++ {
		wsConn, _, err := dialer.Dial(wsURL, nil)
		require.NoError(t, err, fmt.Sprintf("failed to connect to ws server for client %d", i))
		wsConns = append(wsConns, wsConn)
		t.Cleanup(func() {
			if err := wsConn.Close(); err != nil {
				t.Logf("failed to close ws connection: %v", err)
			}
		})
	}

	// Publish 10 messages
	messages := make(map[string]struct{})
	publishURL := fmt.Sprintf("%s/%s/post", ts.URL, apiName)
	for i := 0; i < totalMessages; i++ {
		message := fmt.Sprintf("{\"test\": \"message %d\"}", i)
		messages[message] = struct{}{}

		data := []byte(message)
		resp, err := http.Post(publishURL, "application/json", bytes.NewReader(data))
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	// Read messages from all subscribers
	// Messages are distributed in a round-robin fashion, count the number of messages and check the messages individually.
	var readMessages int
	for readMessages < totalMessages {
		for clientID, wsConn := range wsConns {
			// We need to stop waiting for a message if the subscriber is consumed all of its received messages.
			err := wsConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			require.NoError(t, err, fmt.Sprintf("error while setting read deadline for client %d", clientID))

			_, data, err := wsConn.ReadMessage()
			if os.IsTimeout(err) {
				continue
			}
			require.NoError(t, err, fmt.Sprintf("error while reading message %d", clientID))

			message := string(data)
			_, ok := messages[message]
			require.True(t, ok, fmt.Sprintf("message is unknown or consumed before %s", message))
			delete(messages, message)
			readMessages++
		}
	}
	require.Empty(t, messages)
}

type DummyBase struct {
	model.LoggerProvider
}

func (d *DummyBase) Logger() *logrus.Entry {
	return logrus.NewEntry(logrus.New())
}

func TestStreamingAPIGarbageCollection(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	t.Cleanup(func() {
		ts.Close()
	})

	oasAPI, err := setupOASForStreamAPI(bentoHTTPServerTemplate)
	require.NoError(t, err)

	apiName := "test-api"

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = fmt.Sprintf("/%s", apiName)
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
		spec.OAS.Fill(*spec.APIDefinition)
	})

	apiSpec := streams.NewAPISpec(specs[0].APIID, specs[0].Name, specs[0].IsOAS, specs[0].OAS, specs[0].StripListenPath)

	s := streams.NewMiddleware(ts.Gw, &DummyBase{}, apiSpec, nil)

	if err := setUpStreamAPI(ts, apiName, bentoHTTPServerTemplate); err != nil {
		t.Fatal(err)
	}

	// Dummy request to create a stream manager
	publishURL := fmt.Sprintf("%s/%s/post", ts.URL, apiName)
	r, err := http.NewRequest("POST", publishURL, nil)
	require.NoError(t, err)

	s.CreateStreamManager(r)

	// We should have a Stream manager in the cache.
	var streamManagersBeforeGC int
	s.StreamManagerCache.Range(func(k, v interface{}) bool {
		streamManagersBeforeGC++
		return true
	})
	require.Equal(t, 1, streamManagersBeforeGC)

	s.GC()

	// Garbage collection removed the stream manager because the activity counter is zero.
	var streamManagersAfterGC int
	s.StreamManagerCache.Range(func(k, v interface{}) bool {
		streamManagersAfterGC++
		return true
	})
	require.Equal(t, 0, streamManagersAfterGC)
}
