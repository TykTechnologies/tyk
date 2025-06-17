package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	defaultMQTTBroker = "tcp://localhost:1883"
	defaultTopic      = "tyk-streams-test-topic"
	defaultClientID   = "tyk-mqtt-load-generator"
	defaultQoS        = 1 // QoS 1 - At least once delivery
)

type mqttPayload struct {
	Payload int64 `json:"payload"`
}

type mqttArguments struct {
	help     bool
	broker   string
	topic    string
	clientID string
	qos      int
	username string
	password string
}

type MQTTLoadGenerator struct {
	args mqttArguments
}

func (m *MQTTLoadGenerator) Name() string {
	return "MQTT"
}

func (m *MQTTLoadGenerator) Usage() string {
	return `Usage: go run load_gen.go mqtt [options]

MQTT load generator. Publishes messages to an MQTT broker on the specified topic.

Options:
  -h, --help     Print this message and exit.
      --broker   MQTT broker URL. Default: tcp://localhost:1883.
      --topic    MQTT topic to publish to. Default: tyk-streams-test-topic.
      --clientid MQTT client ID. Default: tyk-mqtt-load-generator.
      --qos      MQTT QoS level (0, 1, or 2). Default: 1.
      --username MQTT username (optional).
      --password MQTT password (optional).
`
}

func (m *MQTTLoadGenerator) ParseArgs() error {
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.BoolVar(&m.args.help, "h", false, "")
	f.BoolVar(&m.args.help, "help", false, "")
	f.StringVar(&m.args.broker, "broker", defaultMQTTBroker, "")
	f.StringVar(&m.args.topic, "topic", defaultTopic, "")
	f.StringVar(&m.args.clientID, "clientid", defaultClientID, "")
	f.IntVar(&m.args.qos, "qos", defaultQoS, "")
	f.StringVar(&m.args.username, "username", "", "")
	f.StringVar(&m.args.password, "password", "", "")

	return f.Parse(os.Args[2:])
}

func (m *MQTTLoadGenerator) Run() {
	if m.args.help {
		fmt.Printf("%s\n", m.Usage())
		return
	}

	if m.args.broker == "" {
		_, _ = fmt.Fprintf(os.Stdout, "broker cannot be empty\n")
		fmt.Printf("%s\n", m.Usage())
		return
	}

	if m.args.topic == "" {
		_, _ = fmt.Fprintf(os.Stdout, "topic cannot be empty\n")
		fmt.Printf("%s\n", m.Usage())
		return
	}

	if m.args.qos < 0 || m.args.qos > 2 {
		_, _ = fmt.Fprintf(os.Stdout, "invalid QoS level: %d (must be 0, 1, or 2)\n", m.args.qos)
		os.Exit(1)
	}

	// Blocking call. Press CTRL+C or send SIGTERM/SIGKILL to stop the script.
	m.publishMessagesWithMQTT(m.args.broker, m.args.topic, m.args.clientID, m.args.qos, m.args.username, m.args.password)
}

func (m *MQTTLoadGenerator) failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

// mqttGeneratePayload creates a JSON-formatted string containing the current Unix time in milliseconds as the payload.
func (m *MQTTLoadGenerator) generatePayload() string {
	result, err := json.Marshal(mqttPayload{time.Now().UnixMilli()})
	m.failOnError(err, "Failed to marshal payload")
	return string(result)
}

// publishMessagesWithMQTT publishes messages to an MQTT broker on the specified topic
// at regular intervals. broker specifies the MQTT broker URL to connect to.
// topic defines the MQTT topic to which messages will be published.
func (m *MQTTLoadGenerator) publishMessagesWithMQTT(broker, topic, clientID string, qos int, username, password string) {
	// MQTT client options
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(clientID)

	// Set credentials if provided
	if username != "" {
		opts.SetUsername(username)
		if password != "" {
			opts.SetPassword(password)
		}
	}

	// Set connection handlers
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		log.Printf("Connected to MQTT broker at %s", broker)
	})
	opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		log.Printf("Connection to MQTT broker lost: %v", err)
	})

	// Create and connect the client
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		m.failOnError(token.Error(), "Failed to connect to MQTT broker")
	}
	defer client.Disconnect(250) // Disconnect with 250ms timeout

	// Publish messages in a loop
	for {
		time.Sleep(1 * time.Second)
		payload := m.generatePayload()
		log.Printf("Publishing message to MQTT topic '%s': %s", topic, payload)

		token := client.Publish(topic, byte(qos), false, payload)
		if token.Wait() && token.Error() != nil {
			m.failOnError(token.Error(), "Failed to publish message")
		}
	}
}
