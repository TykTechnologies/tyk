package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultWebSocketURL = "ws://localhost:8080/ws"
)

type Location struct {
	Name    string `json:"name"`
	Country string `json:"country"`
}

type wsPayload struct {
	Timestamp int64      `json:"timestamp"`
	Locations []Location `json:"locations"`
}

type wsArguments struct {
	help bool
	url  string
}

type WebSocketLoadGenerator struct {
	args wsArguments
}

func (w *WebSocketLoadGenerator) Name() string {
	return "websocket"
}

func (w *WebSocketLoadGenerator) Usage() string {
	return `Usage: load_gen ws [options]

WebSocket load generator. Sends location data to a WebSocket server at the specified URL.

Options:
  -h, --help     Print this message and exit.
      --url      WebSocket server URL. Default: ws://localhost:8080/ws.
`
}

func (w *WebSocketLoadGenerator) ParseArgs() error {
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.BoolVar(&w.args.help, "h", false, "")
	f.BoolVar(&w.args.help, "help", false, "")
	f.StringVar(&w.args.url, "url", defaultWebSocketURL, "")

	return f.Parse(os.Args[2:])
}

func (w *WebSocketLoadGenerator) Run() {
	if w.args.help {
		fmt.Printf("%s\n", w.Usage())
		return
	}

	if w.args.url == "" {
		_, _ = fmt.Fprintf(os.Stdout, "url cannot be empty\n")
		fmt.Printf("%s\n", w.Usage())
		return
	}

	// Blocking call. Press CTRL+C or send SIGTERM/SIGKILL to stop the script.
	w.publishMessagesWithWebSocket(w.args.url)
}

func (w *WebSocketLoadGenerator) failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

// generatePayload creates a JSON-formatted string containing location data.
func (w *WebSocketLoadGenerator) generatePayload() string {
	payload := wsPayload{
		Timestamp: time.Now().UnixMilli(),
		Locations: []Location{
			{Name: "Berlin", Country: "Germany"},
			{Name: "London", Country: "UK"},
			{Name: "Rhodes", Country: "Greece"},
			{Name: "Washington D.C.", Country: "USA"},
			{Name: "Athens", Country: "Greece"},
		},
	}

	result, err := json.Marshal(payload)
	w.failOnError(err, "Failed to marshal payload")
	return string(result)
}

// publishMessagesWithWebSocket publishes messages to a WebSocket server at the specified URL
// at regular intervals.
func (w *WebSocketLoadGenerator) publishMessagesWithWebSocket(url string) {
	// Connect to WebSocket server
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	w.failOnError(err, "Failed to connect to WebSocket server")
	defer c.Close()

	log.Printf("Connected to WebSocket server at %s", url)

	// Send messages in a loop
	for {
		time.Sleep(1 * time.Second)
		payload := w.generatePayload()
		log.Printf("Sending message to WebSocket server: %s", payload)

		err := c.WriteMessage(websocket.TextMessage, []byte(payload))
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			// Try to reconnect
			c, _, err = websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				w.failOnError(err, "Failed to reconnect to WebSocket server")
			}
			log.Printf("Reconnected to WebSocket server at %s", url)
			continue
		}
	}
}
