//go:build ee || dev

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"

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

func createMqttClient(t *testing.T, url, clientID string) mqtt.Client {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(url)
	opts.SetClientID(clientID)

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
		doneChan := listenToWebsocketMessage(t, ts, apiName, 1, numMessages)
		client := createMqttClient(t, brokerURL, clientID)

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
		t.Cleanup(func() {
			conn.Close()
		})
		wsClients[i] = conn
		require.NoError(t, err)
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
