//go:build ee || dev

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	amqp1 "github.com/Azure/go-amqp"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/rabbitmq"
)

func setupOASForStreamingAPIWithAMQP(t *testing.T, streamingConfig string) oas.OAS {
	t.Helper()

	streamingConfigJSON, err := ConvertYAMLToJSON([]byte(streamingConfig))
	require.NoErrorf(t, err, "Failed to convert YAML to JSON: %v", streamingConfigJSON)

	var parsedStreamingConfig map[string]interface{}
	err = json.Unmarshal(streamingConfigJSON, &parsedStreamingConfig)
	require.NoErrorf(t, err, "Failed to unmarshal JSON: %v", streamingConfigJSON)

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

func setupStreamingAPIForAMQP(t *testing.T, ts *Test, tykStreamOAS *oas.OAS) string {
	t.Helper()

	apiName := fmt.Sprintf("streaming-api-amqp-%s", uuid.New().String())
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = fmt.Sprintf("/%s", apiName)
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = *tykStreamOAS
		spec.OAS.Fill(*spec.APIDefinition)
		spec.EnableContextVars = true
	})

	return apiName
}

func amqp1Publisher(t *testing.T, amqpURL string, queueName string, messages [][]byte) {
	ctx := context.Background()
	conn, err := amqp1.Dial(ctx, amqpURL, nil)
	require.NoErrorf(t, err, "Failed to connect to RabbitMQ")

	session, err := conn.NewSession(ctx, nil)
	require.NoErrorf(t, err, "Failed to create a session")
	// send a message

	// create a new sender
	sender, err := session.NewSender(ctx, queueName, nil)
	require.NoError(t, err, "Failed to create a sender")

	for _, message := range messages {
		err = sender.Send(ctx, amqp1.NewMessage(message), nil)
		require.NoError(t, err, "Failed to send a message")
	}
}

func amqp09Publisher(t *testing.T, amqpURL string, queueName string, messages [][]byte) {
	const exchangeName = "test-exchange"

	conn, err := amqp091.Dial(amqpURL)
	require.NoErrorf(t, err, "Failed to connect to RabbitMQ")
	defer func() {
		require.NoError(t, conn.Close())
	}()

	ch, err := conn.Channel()
	require.NoErrorf(t, err, "Failed to open a channel")
	defer func() {
		require.NoError(t, ch.Close())
	}()

	t.Log("Channel opened")

	err = ch.ExchangeDeclare(
		exchangeName, // name
		"fanout",     // type
		true,         // durable
		false,        // auto-deleted
		false,        // internal
		false,        // no-wait
		nil,          // arguments
	)
	require.NoErrorf(t, err, "Failed to declare an exchange")
	t.Logf("Exchange declared: %s", exchangeName)

	queue, err := ch.QueueDeclare(
		queueName, // name of the queue
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // noWait
		nil,       // arguments
	)
	require.NoErrorf(t, err, "Failed to declare a queue")
	t.Logf("Queue declared: %s", queue.Name)

	err = ch.QueueBind(queue.Name, "", exchangeName, false, nil)
	require.NoErrorf(t, err, "Failed to bind a queue")
	t.Logf("Queue binded: %s", queueName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, message := range messages {
		err = ch.PublishWithContext(ctx,
			exchangeName, // exchange
			"",           // routing key
			false,        // mandatory
			false,        // immediate
			amqp091.Publishing{
				ContentType: "application/octet-stream",
				Body:        message,
			})
	}
}

func createWebsocketClients(t *testing.T, ts *Test, apiName string, numClients int) []*websocket.Conn {
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
			data, _ := io.ReadAll(resp.Body)
			fmt.Println(string(data))
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
	return wsClients
}

func testAMQPPublisherWebsocketConsumer(t *testing.T, ts *Test, queue string, input string, amqpURL string, apiName string) {
	t.Helper()

	const (
		messageToSend = "hello amqp"
		numMessages   = 2
		numClients    = 2
	)

	// Create WebSocket clients
	wsClients := createWebsocketClients(t, ts, apiName, numClients)

	// Publish messages to the AMQP Broker
	messages := make([][]byte, numMessages)
	for i := 0; i < numMessages; i++ {
		messages[i] = []byte(messageToSend + "-" + strconv.Itoa(i))
	}

	if input == "amqp_0_9" {
		amqp09Publisher(t, amqpURL, queue, messages)
	} else if input == "amqp_1" {
		amqp1Publisher(t, amqpURL, queue, messages)
	} else {
		require.Fail(t, "Invalid input type")
	}

	expectedTotalMessages := numMessages
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
					if err := wsConn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
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

	t.Logf("Final message count: %d out of %d expected", messagesReceived, expectedTotalMessages)
	if messagesReceived != expectedTotalMessages {
		t.Errorf("Expected %d messages, but received %d", expectedTotalMessages, messagesReceived)
	} else {
		t.Logf("Successfully received %d messages as expected", messagesReceived)
	}

	t.Log("Test completed, closing WebSocket connections")
}

func Test_TykStreaming_AMQP(t *testing.T) {
	ctx := context.Background()
	rabbitmqContainer, err := rabbitmq.Run(ctx,
		"rabbitmq:4.0.8-management-alpine",
		rabbitmq.WithAdminUsername("guest"),
		rabbitmq.WithAdminPassword("guest"),
	)
	defer func() {
		terminateErr := testcontainers.TerminateContainer(rabbitmqContainer)
		require.NoError(t, terminateErr)
	}()
	require.NoError(t, err)

	amqpURL, err := rabbitmqContainer.AmqpURL(ctx)
	require.NoError(t, err)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	defer ts.Close()

	t.Run("Publish messages to amqp_0_9 input then consume messages via Websocket", func(t *testing.T) {
		queueName := "test-queue-amqp-0-9"
		streamingConfig := fmt.Sprintf(`
streams:
  test:
    input:
      label: ""
      amqp_0_9:
        urls: [%s]
        queue: "%s"
        consumer_tag: ""
        prefetch_count: 10
    output:
      http_server:
        path: /get
        ws_path: /get/ws
`, amqpURL, queueName)
		tykStreamingOAS := setupOASForStreamingAPIWithAMQP(t, streamingConfig)
		apiName := setupStreamingAPIForAMQP(t, ts, &tykStreamingOAS)
		testAMQPPublisherWebsocketConsumer(t, ts, queueName, "amqp_0_9", amqpURL, apiName)
	})

	t.Run("Publish messages to amqp_1 input then consume messages via Websocket", func(t *testing.T) {
		queueName := "test-queue-amqp-1"
		streamingConfig := fmt.Sprintf(`
streams:
  test:
    input:
      label: ""
      amqp_1:
        urls: [%s]
        source_address: "%s"
    output:
      http_server:
        path: /get
        ws_path: /get/ws
`, amqpURL, queueName)
		tykStreamingOAS := setupOASForStreamingAPIWithAMQP(t, streamingConfig)
		apiName := setupStreamingAPIForAMQP(t, ts, &tykStreamingOAS)
		testAMQPPublisherWebsocketConsumer(t, ts, queueName, "amqp_1", amqpURL, apiName)
	})
}
