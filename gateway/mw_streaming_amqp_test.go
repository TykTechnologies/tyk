//go:build ee || dev

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/rabbitmq"
)

type amqpTestContext struct {
	t            *testing.T
	ts           *Test
	apiName      string
	exchangeName string
	queueName    string
	amqpURL      string
	input        string
	output       string
}

func initializeAMQP09Environment(testCtx *amqpTestContext) {
	conn, err := amqp091.Dial(testCtx.amqpURL)
	require.NoError(testCtx.t, err, "Failed to connect to RabbitMQ")

	defer conn.Close()

	ch, err := conn.Channel()
	require.NoError(testCtx.t, err, "Failed to open an AMQP09 channel")

	defer ch.Close()

	err = ch.ExchangeDeclare(
		testCtx.exchangeName, // name
		"fanout",             // type
		true,                 // durable
		false,                // auto-deleted
		false,                // internal
		false,                // no-wait
		nil,                  // arguments
	)
	require.NoError(testCtx.t, err, "Failed to declare an exchange")

	_, err = ch.QueueDeclare(
		testCtx.queueName, // name
		true,              // durable
		false,             // delete when unused
		false,             // exclusive
		false,             // no-wait
		nil,               // arguments
	)
	require.NoError(testCtx.t, err, "Failed to declare a queue")

	err = ch.QueueBind(
		testCtx.queueName,    // queue name
		"",                   // routing key
		testCtx.exchangeName, // exchange
		false,
		nil,
	)
}

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

func amqp09Publisher(testCtx *amqpTestContext, messages [][]byte) {
	conn, err := amqp091.Dial(testCtx.amqpURL)
	require.NoErrorf(testCtx.t, err, "Failed to connect to RabbitMQ")
	defer func() {
		require.NoError(testCtx.t, conn.Close())
	}()

	ch, err := conn.Channel()
	require.NoErrorf(testCtx.t, err, "Failed to open a channel")
	defer func() {
		require.NoError(testCtx.t, ch.Close())
	}()

	testCtx.t.Log("Channel opened")

	err = ch.ExchangeDeclare(
		testCtx.exchangeName, // name
		"fanout",             // type
		true,                 // durable
		false,                // auto-deleted
		false,                // internal
		false,                // no-wait
		nil,                  // arguments
	)
	require.NoErrorf(testCtx.t, err, "Failed to declare an exchange")
	testCtx.t.Logf("Exchange declared: %s", testCtx.exchangeName)

	queue, err := ch.QueueDeclare(
		testCtx.queueName, // name of the queue
		true,              // durable
		false,             // delete when unused
		false,             // exclusive
		false,             // noWait
		nil,               // arguments
	)
	require.NoErrorf(testCtx.t, err, "Failed to declare a queue")
	testCtx.t.Logf("Queue declared: %s", queue.Name)

	err = ch.QueueBind(queue.Name, "", testCtx.exchangeName, false, nil)
	require.NoErrorf(testCtx.t, err, "Failed to bind a queue")
	testCtx.t.Logf("Queue binded: %s", testCtx.queueName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, message := range messages {
		err = ch.PublishWithContext(ctx,
			testCtx.exchangeName, // exchange
			"",                   // routing key
			false,                // mandatory
			false,                // immediate
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

func testWebsocketOutput(t *testing.T, wsClients []*websocket.Conn, messageToSend string, numMessages int) {
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

func testAMQP09Output(testCtx *amqpTestContext, expectedMessages [][]byte) {
	conn, err := amqp091.Dial(testCtx.amqpURL)
	require.NoError(testCtx.t, err, "Failed to connect to RabbitMQ")

	defer conn.Close()

	ch, err := conn.Channel()
	require.NoError(testCtx.t, err, "Failed to open an AMQP09 channel")

	defer ch.Close()

	msgs, err := ch.Consume(
		testCtx.queueName, // queue
		"consumer",        // consumer
		true,              // auto-ack
		false,             // exclusive
		false,             // no-local
		false,             // no-wait
		nil,               // args
	)
	require.NoError(testCtx.t, err, "Failed to consume messages")
	done := make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result [][]byte
	go func() {
		for d := range msgs {
			result = append(result, d.Body)
			if len(result) == len(expectedMessages) {
				close(done)
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}

	assert.Equal(testCtx.t, expectedMessages, result)
}

func testTykStreamAMQPIntegration(testCtx *amqpTestContext) {
	testCtx.t.Helper()

	const (
		messageToSend = "hello amqp"
		numMessages   = 2
		numClients    = 2
	)

	var wsClients []*websocket.Conn
	if testCtx.output == "websocket" {
		// Create WebSocket clients
		wsClients = createWebsocketClients(testCtx.t, testCtx.ts, testCtx.apiName, numClients)
	}

	// Publish messages to the AMQP Broker
	messages := make([][]byte, numMessages)
	for i := 0; i < numMessages; i++ {
		messages[i] = []byte(messageToSend + "-" + strconv.Itoa(i))
	}

	if testCtx.input == "amqp_0_9" {
		amqp09Publisher(testCtx, messages)
	} else if testCtx.input == "amqp_1" {
		amqp1Publisher(testCtx.t, testCtx.amqpURL, testCtx.queueName, messages)
	} else if testCtx.input == "http_server" {
		publishURL := fmt.Sprintf("%s/%s/post", testCtx.ts.URL, testCtx.apiName)
		for _, message := range messages {
			resp, err := http.Post(publishURL, "application/json", bytes.NewReader(message))
			require.NoError(testCtx.t, err)
			data, _ := io.ReadAll(resp.Body)
			fmt.Println(string(data))
			_ = resp.Body.Close()
		}
	} else {
		require.Fail(testCtx.t, "Invalid input type")
	}

	if testCtx.output == "websocket" {
		testWebsocketOutput(testCtx.t, wsClients, messageToSend, numMessages)
	} else if testCtx.output == "amqp_0_9" {
		testAMQP09Output(testCtx, messages)
	}
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

	const exchangeName = "test-exchange"

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
		testCtx := &amqpTestContext{
			t:            t,
			ts:           ts,
			apiName:      apiName,
			queueName:    queueName,
			exchangeName: exchangeName,
			amqpURL:      amqpURL,
			input:        "amqp_0_9",
			output:       "websocket",
		}
		initializeAMQP09Environment(testCtx)
		testTykStreamAMQPIntegration(testCtx)
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
		testContext := &amqpTestContext{
			t:            t,
			ts:           ts,
			apiName:      apiName,
			queueName:    queueName,
			exchangeName: exchangeName,
			amqpURL:      amqpURL,
			input:        "amqp_1",
			output:       "websocket",
		}
		testTykStreamAMQPIntegration(testContext)
	})

	t.Run("Publish messages to http input then consume messages from amqp_9 output", func(t *testing.T) {
		queueName := "test-queue-amqp-0-9-input-output"
		streamingConfig := fmt.Sprintf(`
streams:
  test:
    input:
      http_server:
        path: /post
        timeout: 1s
    output:
      amqp_0_9:
        urls: [%s]
        exchange: "%s"
`, amqpURL, exchangeName)
		tykStreamingOAS := setupOASForStreamingAPIWithAMQP(t, streamingConfig)
		apiName := setupStreamingAPIForAMQP(t, ts, &tykStreamingOAS)
		testCtx := &amqpTestContext{
			t:            t,
			ts:           ts,
			apiName:      apiName,
			queueName:    queueName,
			exchangeName: exchangeName,
			amqpURL:      amqpURL,
			input:        "http_server",
			output:       "amqp_0_9",
		}
		initializeAMQP09Environment(testCtx)
		testTykStreamAMQPIntegration(testCtx)
	})
}
