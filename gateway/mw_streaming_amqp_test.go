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
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	amqp1 "github.com/Azure/go-amqp"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/rabbitmq"
)

const (
	AlivenessCheckPath    = "/api/aliveness-test/"
	DefaultVirtualHost    = "/"
	RabbitmqAdminUsername = "guest"
	RabbitmqAdminPassword = "guest"
)

type alivenessCheckResponse struct {
	Status string `json:"status"`
}

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

func (t *amqpTestContext) publishHTTPMessage(contentType string, message []byte) {
	publishURL := fmt.Sprintf("%s/%s/post", t.ts.URL, t.apiName)
	resp, err := http.Post(publishURL, contentType, bytes.NewReader(message))
	require.NoError(t.t, err)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t.t, err)
	if data != nil {
		t.t.Logf("Received response: %s", string(data))
	}

	_ = resp.Body.Close()
}

func randomExchangeName() string {
	return fmt.Sprintf("test-exchange-%s", uuid.New().String())
}

func (t *amqpTestContext) initializeAMQP09Environment() {
	conn, err := amqp091.Dial(t.amqpURL)
	require.NoError(t.t, err, "Failed to connect to RabbitMQ")

	defer conn.Close()

	ch, err := conn.Channel()
	require.NoError(t.t, err, "Failed to open an AMQP09 channel")

	defer ch.Close()

	err = ch.ExchangeDeclare(
		t.exchangeName, // name
		"fanout",       // type
		true,           // durable
		false,          // auto-deleted
		false,          // internal
		false,          // no-wait
		nil,            // arguments
	)
	require.NoError(t.t, err, "Failed to declare an exchange")

	_, err = ch.QueueDeclare(
		t.queueName, // name
		true,        // durable
		false,       // delete when unused
		false,       // exclusive
		false,       // no-wait
		nil,         // arguments
	)
	require.NoError(t.t, err, "Failed to declare a queue")

	err = ch.QueueBind(
		t.queueName,    // queue name
		"",             // routing key
		t.exchangeName, // exchange
		false,
		nil,
	)
	t.t.Logf("AMQP-0.9 queue: %s bound to exchange: %s", t.queueName, t.exchangeName)
}

func setupStreamingAPIForOAS(t *testing.T, ts *Test, tykStreamOAS *oas.OAS) string {
	t.Helper()

	apiName := fmt.Sprintf("streaming-api-%s", uuid.New().String())
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

	// create a new sender
	sender, err := session.NewSender(ctx, queueName, nil)
	require.NoError(t, err, "Failed to create a sender")

	for _, message := range messages {
		err = sender.Send(ctx, amqp1.NewMessage(message), nil)
		require.NoError(t, err, "Failed to send a message")
	}
}

func (t *amqpTestContext) amqp09Publisher(messages [][]byte) {
	conn, err := amqp091.Dial(t.amqpURL)
	require.NoErrorf(t.t, err, "Failed to connect to RabbitMQ")
	defer func() {
		require.NoError(t.t, conn.Close())
	}()

	ch, err := conn.Channel()
	require.NoErrorf(t.t, err, "Failed to open a channel")
	defer func() {
		require.NoError(t.t, ch.Close())
	}()

	t.t.Log("Channel opened")

	err = ch.ExchangeDeclare(
		t.exchangeName, // name
		"fanout",       // type
		true,           // durable
		false,          // auto-deleted
		false,          // internal
		false,          // no-wait
		nil,            // arguments
	)
	require.NoErrorf(t.t, err, "Failed to declare an exchange")
	t.t.Logf("Exchange declared: %s", t.exchangeName)

	queue, err := ch.QueueDeclare(
		t.queueName, // name of the queue
		true,        // durable
		false,       // delete when unused
		false,       // exclusive
		false,       // noWait
		nil,         // arguments
	)
	require.NoErrorf(t.t, err, "Failed to declare a queue")
	t.t.Logf("Queue declared: %s", queue.Name)

	err = ch.QueueBind(queue.Name, "", t.exchangeName, false, nil)
	require.NoErrorf(t.t, err, "Failed to bind a queue")
	t.t.Logf("Queue binded: %s", t.queueName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, message := range messages {
		err = ch.PublishWithContext(ctx,
			t.exchangeName, // exchange
			"",             // routing key
			false,          // mandatory
			false,          // immediate
			amqp091.Publishing{
				ContentType: "text/plain",
				Body:        message,
			})
	}
}

func (t *amqpTestContext) createWebsocketClients(numClients int) []*websocket.Conn {
	// Create WebSocket clients
	wsClients := make([]*websocket.Conn, numClients)
	for i := 0; i < numClients; i++ {
		dialer := websocket.Dialer{
			HandshakeTimeout: 5 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		}
		wsURL := strings.Replace(t.ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/get/ws", t.apiName)
		wsConn, resp, err := dialer.Dial(wsURL, nil)
		if err != nil {
			if resp != nil {
				data, _ := io.ReadAll(resp.Body)
				require.FailNow(t.t, "Failed to connect to WebSocket %d: %v\nStatusCode: %d\nResponse: %+v", i, err, resp.StatusCode, data)
			} else {
				require.FailNow(t.t, "Failed to connect to WebSocket %d: %v\n", i, err)
			}
		}
		t.t.Cleanup(func() {
			if err = wsConn.Close(); err != nil {
				t.t.Logf("Failed to close WebSocket %d: %v", i, err)
			}
		})
		wsClients[i] = wsConn
		t.t.Logf("Successfully connected to WebSocket %d", i)
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

func (t *amqpTestContext) testAMQP09Output(expectedMessages [][]byte) {
	conn, err := amqp091.Dial(t.amqpURL)
	require.NoError(t.t, err, "Failed to connect to RabbitMQ")

	defer conn.Close()

	ch, err := conn.Channel()
	require.NoError(t.t, err, "Failed to open an AMQP09 channel")

	defer ch.Close()

	msgs, err := ch.Consume(
		t.queueName, // queue
		"consumer",  // consumer
		true,        // auto-ack
		false,       // exclusive
		false,       // no-local
		false,       // no-wait
		nil,         // args
	)
	require.NoError(t.t, err, "Failed to consume messages")
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

	assert.Equal(t.t, expectedMessages, result)
}

func (t *amqpTestContext) testTykStreamAMQPIntegration() {
	t.t.Helper()

	const (
		messageToSend = "hello amqp"
		numMessages   = 2
		numClients    = 2
	)

	var wsClients []*websocket.Conn
	if t.output == "websocket" {
		// Create WebSocket clients
		wsClients = t.createWebsocketClients(numClients)
	}

	// Publish messages to the AMQP Broker
	messages := make([][]byte, numMessages)
	for i := 0; i < numMessages; i++ {
		messages[i] = []byte(messageToSend + "-" + strconv.Itoa(i))
	}

	if t.input == "amqp_0_9" {
		t.amqp09Publisher(messages)
	} else if t.input == "amqp_1" {
		amqp1Publisher(t.t, t.amqpURL, t.queueName, messages)
	} else if t.input == "http_server" {
		for _, message := range messages {
			t.publishHTTPMessage("text/plain", message)
		}
	} else {
		require.Fail(t.t, "Invalid input type")
	}

	if t.output == "websocket" {
		testWebsocketOutput(t.t, wsClients, messageToSend, numMessages)
	} else if t.output == "amqp_0_9" {
		t.testAMQP09Output(messages)
	} else {
		require.Fail(t.t, "Invalid output type")
	}
}

// checkRabbitMQAliveness verifies the RabbitMQ management endpoint for its
// aliveness status with retries until a timeout occurs. It performs health checks
// by querying the management API and ensures RabbitMQ is ready for further integration tests.
func checkRabbitMQAliveness(t *testing.T, rabbitmqContainer *rabbitmq.RabbitMQContainer) {
	managementURL, err := rabbitmqContainer.HttpURL(context.Background())
	require.NoError(t, err)

	parsedUrl, err := url.Parse(managementURL)
	require.NoError(t, err)

	parsedUrl.Path = AlivenessCheckPath
	parsedUrl.User = url.UserPassword(RabbitmqAdminUsername, RabbitmqAdminPassword)
	alivenessCheckURL, err := url.JoinPath(parsedUrl.String(), url.PathEscape(DefaultVirtualHost))
	require.NoError(t, err)

	const interval = 250 * time.Millisecond
	duration, err := time.ParseDuration("5s")
	require.NoError(t, err)

	checkAliveness := func() bool {
		resp, reqErr := http.Get(alivenessCheckURL)
		if reqErr != nil {
			t.Logf("Failed to check RabbitMQ aliveness: %v", reqErr)
			return false
		}

		defer func() {
			require.NoError(t, resp.Body.Close())
		}()

		// status code might be 404 if the virtual host doesn't exist.
		if resp.StatusCode != http.StatusOK {
			return false
		}

		data, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)

		response := &alivenessCheckResponse{}
		require.NoError(t, json.Unmarshal(data, response))
		return response.Status == "ok"
	}

	maxAttempts := int(duration.Milliseconds() / interval.Milliseconds())
	for attempt := 0; attempt < maxAttempts; attempt++ {
		time.Sleep(interval)
		if rabbitmqContainer.IsRunning() {
			if checkAliveness() {
				// It's alive, let's start running the integration tests.
				return
			}
		}
		t.Logf("RabbitMQ is not ready to accept requests, attempt %d/%d", attempt+1, maxAttempts)
	}

	require.Fail(t, "RabbitMQ is not alive after %d attempts", maxAttempts)
}

func TestAMQP(t *testing.T) {
	ctx := context.Background()
	rabbitmqContainer, err := rabbitmq.Run(ctx,
		"rabbitmq:4.0.8-management-alpine",
		rabbitmq.WithAdminUsername(RabbitmqAdminUsername),
		rabbitmq.WithAdminPassword(RabbitmqAdminPassword),
	)
	defer func() {
		terminateErr := testcontainers.TerminateContainer(rabbitmqContainer)
		require.NoError(t, terminateErr)
	}()
	require.NoError(t, err)

	checkRabbitMQAliveness(t, rabbitmqContainer)

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
    output:
      http_server:
        path: /get
        ws_path: /get/ws
`, amqpURL, queueName)
		tykStreamingOAS, oasErr := setupOASForStreamAPI(streamingConfig)
		require.NoError(t, oasErr)
		apiName := setupStreamingAPIForOAS(t, ts, &tykStreamingOAS)
		testCtx := &amqpTestContext{
			t:            t,
			ts:           ts,
			apiName:      apiName,
			queueName:    queueName,
			exchangeName: randomExchangeName(),
			amqpURL:      amqpURL,
			input:        "amqp_0_9",
			output:       "websocket",
		}
		testCtx.initializeAMQP09Environment()
		testCtx.testTykStreamAMQPIntegration()
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
		tykStreamingOAS, oasErr := setupOASForStreamAPI(streamingConfig)
		require.NoError(t, oasErr)
		apiName := setupStreamingAPIForOAS(t, ts, &tykStreamingOAS)
		testContext := &amqpTestContext{
			t:            t,
			ts:           ts,
			apiName:      apiName,
			queueName:    queueName,
			exchangeName: randomExchangeName(),
			amqpURL:      amqpURL,
			input:        "amqp_1",
			output:       "websocket",
		}
		testContext.testTykStreamAMQPIntegration()
	})

	t.Run("Publish messages to http input then consume messages from amqp_9 output", func(t *testing.T) {
		queueName := "test-queue-input-http-amqp-0-9-output"
		exchangeName := randomExchangeName()
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
		tykStreamingOAS, oasErr := setupOASForStreamAPI(streamingConfig)
		require.NoError(t, oasErr)
		apiName := setupStreamingAPIForOAS(t, ts, &tykStreamingOAS)
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
		testCtx.initializeAMQP09Environment()
		testCtx.testTykStreamAMQPIntegration()
	})
}
