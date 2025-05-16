//go:build ee || dev

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/gorilla/websocket"
	"github.com/testcontainers/testcontainers-go/wait"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func startEclipseMosquittoContainer(t *testing.T) string {
	configFile := `
listener 1883
allow_anonymous true
`

	req := testcontainers.ContainerRequest{
		Image:        "eclipse-mosquitto:2.0.21",
		ExposedPorts: []string{"1883/tcp"},
		WaitingFor:   wait.ForLog("mosquitto version 2.0.21 running"),
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader(configFile),
				ContainerFilePath: "/mosquitto/config/mosquitto.conf",
			},
		},
	}

	container, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		err := testcontainers.TerminateContainer(container)
		require.NoError(t, err)
	})

	url, err := container.PortEndpoint(context.Background(), "1883/tcp", "tcp")
	require.NoError(t, err)
	return url
}

func createMqttClient(t *testing.T, url, clientID string, optModifier func(o *mqtt.ClientOptions)) mqtt.Client {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(url)
	opts.SetClientID(clientID)

	if optModifier != nil {
		optModifier(opts)
	}

	client := mqtt.NewClient(opts)
	token := client.Connect()
	t.Cleanup(func() {
		client.Disconnect(250)
	})
	require.True(t, token.WaitTimeout(10*time.Second))
	err := token.Error()
	require.NoError(t, err)

	return client
}

func TestMQTT(t *testing.T) {

	// Start MQTT container
	brokerURL := startEclipseMosquittoContainer(t)
	clientID := "test-client"

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	defer ts.Close()

	t.Run("publish messages to mosquito and consume via websockets", func(t *testing.T) {
		topic := "tyk-test"
		streamingConfig := fmt.Sprintf(`
streams:
  test:
    input:
      label: ""
      mqtt:
        urls: [%s]
        client_id: "bento-client"
        topics: [%s]
    output:
      http_server:
        path: /get
        ws_path: /get/ws	
`, brokerURL, topic)

		numMessages := 3
		streamingOAS, err := setupOASForStreamAPI(streamingConfig)
		require.NoError(t, err)

		apiName := setupStreamingAPIForOAS(t, ts, &streamingOAS)
		doneChan := listenToWebsocketMessage(t, ts, apiName, 2, numMessages)
		client := createMqttClient(t, brokerURL, clientID, nil)

		for i := 0; i < numMessages; i++ {
			timer := time.After(5 * time.Second)
			token := client.Publish(topic, 2, false, "test payload")
			token.Wait()
			select {
			case <-timer:
				t.Fatal("Timed out waiting for publish to mosquitto")
			case <-token.Done():
			}
			require.NoError(t, token.Error())
		}

		timeout := time.After(10 * time.Second)
		select {
		case <-doneChan:
		case <-timeout:
			assert.FailNow(t, "timeout waiting for message from websocket")
		}
	})

	t.Run("publish messages to http input and consume via mqtt", func(t *testing.T) {
		streamConfig := fmt.Sprintf(`
streams:
  test:
    input:
      http_server:
        path: /post
        timeout: 1s
    output:
      mqtt:
        urls: [%s]
        client_id: bento-client
        topic: tyk-test
        connect_timeout: 5s
`, brokerURL)

		streamingOAS, err := setupOASForStreamAPI(streamConfig)
		require.NoError(t, err)

		numMessages := 3
		apiName := setupStreamingAPIForOAS(t, ts, &streamingOAS)
		doneChan := listenToAMQTT(t, brokerURL, "tyk-client", "tyk-test", 3)
		publishHTTPMessage(t, fmt.Sprintf("%s/%s", ts.URL, apiName), []byte("hello"), numMessages)

		totalTimeout := time.After(10 * time.Second)
		select {
		case <-doneChan:
		case <-totalTimeout:
			t.Fatal("Timed out waiting for message from mqtt")
		}
	})
}

func listenToWebsocketMessage(t *testing.T, ts *Test, apiName string, numClients int, numMessages int) chan struct{} {
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}
	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + fmt.Sprintf("/%s/get/ws", apiName)
	wsClients := make([]*websocket.Conn, numClients)
	for i := 0; i < numClients; i++ {
		conn, _, err := dialer.Dial(wsURL, nil)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, conn.Close())
		})
		wsClients[i] = conn
	}

	doneChan := make(chan struct{})
	go func() {
		receivedMessages := 0
		for {
			for i, conn := range wsClients {
				err := conn.SetReadDeadline(time.Now().Add(10 * time.Hour))
				require.NoError(t, err)
				_, _, err = conn.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						t.Logf("Unexpected error reading from WebSocket %d: %v", i+1, err)
					}
				} else {
					receivedMessages++
					if receivedMessages >= numMessages {
						doneChan <- struct{}{}
						return
					}
				}
			}
		}
	}()
	return doneChan
}

func listenToAMQTT(t *testing.T, brokerURL, clientID, topic string, total int) (done chan struct{}) {
	done = make(chan struct{})
	choke := make(chan [2]string)
	client := createMqttClient(t, brokerURL, clientID, func(o *mqtt.ClientOptions) {
		o.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
			choke <- [2]string{msg.Topic(), string(msg.Payload())}
		})
	})

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	if token := client.Subscribe(topic, 1, nil); token.Wait() && token.Error() != nil {
		require.NoError(t, token.Error())
	}

	go func() {
		receiveCount := 0
		for receiveCount < total {
			listenTimer := time.NewTimer(time.Second * 10)
			select {
			case <-listenTimer.C:
				return
			case incoming := <-choke:
				t.Logf("RECEIVED TOPIC: %s MESSAGE: %s\n", incoming[0], incoming[1])
				receiveCount++
			}
		}
		done <- struct{}{}
	}()

	return done
}

func publishHTTPMessage(t *testing.T, url string, message []byte, count int) {
	publishURL := fmt.Sprintf("%s/post", url)
	for i := 0; i < count; i++ {
		resp, err := http.Post(publishURL, "text/plain", bytes.NewReader(message))
		require.NoError(t, err)

		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		if data != nil {
			t.Logf("Received response: %s", string(data))
		}

		_ = resp.Body.Close()
	}

}
