package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	amqp1 "github.com/Azure/go-amqp"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	protocolAmqp09      = "amqp_0_9"
	protocolAmqp1       = "amqp_1"
	defaultQueueName    = "tyk-streams-test-queue"
	defaultExchangeName = "tyk-streams-test-exchange"
	defaultAMQPURL      = "amqp://guest:guest@localhost:5672/"
)

func usage() {
	var msg = `Usage: amqp_load_generator [options]

AMQP load generator. Publishes messages to a RabbitMQ queue using the specified protocol.

Options:
  -h, --help     Print this message and exit.
      --protocol AMQP protocol version to use. Supported values: amqp_0_9, amqp_1. Default: amqp_0_9.
      --url      RabbitMQ server URL. Default: amqp://guest:guest@localhost:5672/.
      --queue    RabbitMQ queue name. Default: tyk-streams-test-queue.
      --exchange RabbitMQ exchange name, only valid for amqp_0_9 Default: tyk-streams-test-exchange.
`
	_, err := fmt.Fprint(os.Stdout, msg)
	if err != nil {
		panic(err)
	}
}

type payload struct {
	Payload int64 `json:"payload"`
}

type arguments struct {
	help     bool
	protocol string
	url      string
	queue    string
	exchange string
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

// generatePayload creates a JSON-formatted string containing the current Unix time in milliseconds as the payload.
func generatePayload() string {
	result, err := json.Marshal(payload{time.Now().UnixMilli()})
	failOnError(err, "Failed to marshal payload")
	return string(result)
}

// publishMessagesWithAMQP09 publishes messages to a RabbitMQ queue using the
// AMQP 0.9.1 protocol at regular intervals. url specifies the RabbitMQ server
// URL to connect to. queue defines the name of the RabbitMQ queue to which
// messages will be published.
func publishMessagesWithAMQP09(url string, exchange string, queue string) {
	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	err = ch.ExchangeDeclare(
		exchange, // name
		"fanout", // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare(
		queue, // name
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	failOnError(err, "Failed to declare a queue")

	err = ch.QueueBind(queue, "", exchange, false, nil)
	failOnError(err, "Failed to bind a queue")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		time.Sleep(1 * time.Second)
		payload := generatePayload()
		log.Printf("Publishing message to %s '%s'\n", protocolAmqp09, payload)
		err = ch.PublishWithContext(ctx,
			exchange, // exchange
			q.Name,   // routing key
			false,    // mandatory
			false,    // immediate
			amqp.Publishing{
				ContentType: "application/json",
				Body:        []byte(payload),
			})
		failOnError(err, "Failed to publish a message")
	}
}

// publishMessagesWithAMQP1 publishes messages to a RabbitMQ queue using the AMQP 1.0
// protocol at regular intervals. url specifies the AMQP 1.0 server URL to connect to.
// queue defines the name of the RabbitMQ queue to publish messages.
func publishMessagesWithAMQP1(url string, queue string) {
	ctx := context.Background()
	conn, err := amqp1.Dial(ctx, url, nil)
	failOnError(err, "Failed to connect to RabbitMQ")

	session, err := conn.NewSession(ctx, nil)
	failOnError(err, "Failed to create amqp_1 session")

	// create a new sender
	sender, err := session.NewSender(ctx, queue, nil)
	failOnError(err, "Failed to create amqp_1 sender")

	// send a message
	for {
		time.Sleep(1 * time.Second)
		payload := generatePayload()
		log.Printf("Publishing message to %s '%s'", protocolAmqp1, payload)
		err = sender.Send(ctx, amqp1.NewMessage([]byte(payload)), nil)
		failOnError(err, "Failed to send a message")
	}
}

func main() {
	var args arguments

	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	f.SetOutput(ioutil.Discard)
	f.BoolVar(&args.help, "h", false, "")
	f.BoolVar(&args.help, "help", false, "")
	f.StringVar(&args.protocol, "protocol", protocolAmqp09, "")
	f.StringVar(&args.queue, "queue", defaultQueueName, "")
	f.StringVar(&args.url, "url", defaultAMQPURL, "")
	f.StringVar(&args.exchange, "exchange", defaultExchangeName, "")

	if err := f.Parse(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "failed to parse arguments: %v\n", err)
		usage()
		os.Exit(1)
	}

	if args.help {
		usage()
		return
	}

	if args.protocol == "" {
		_, _ = fmt.Fprintf(os.Stdout, "protocol cannot be empty\n")
		usage()
		return
	}

	if args.url == "" {
		_, _ = fmt.Fprintf(os.Stdout, "url cannot be empty\n")
		usage()
		return
	}

	if args.protocol != protocolAmqp09 && args.protocol != protocolAmqp1 {
		_, _ = fmt.Fprintf(os.Stdout, "invalid protocol: %s\n", args.protocol)
		os.Exit(1)
	}

	// Blocking calls. Press CTRL+C or send SIGTERM/SIGKILL to stop the script.
	if args.protocol == protocolAmqp09 {
		publishMessagesWithAMQP09(args.url, args.exchange, args.queue)
	} else if args.protocol == protocolAmqp1 {
		publishMessagesWithAMQP1(args.url, args.queue)
	}
}
