package main

import (
	"fmt"
	"os"
)

type LoadGenerator interface {
	Name() string
	Usage() string
	ParseArgs() error
	Run()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run load_gen.go <type>")
		return
	}

	var loadGen LoadGenerator
	switch os.Args[1] {
	case "mqtt":
		loadGen = &MQTTLoadGenerator{}
	case "amqp":
		loadGen = &AMQPLoadGenerator{}
	case "ws":
		loadGen = &WebSocketLoadGenerator{}
	default:
		fmt.Printf("Unknown load generator type: %s\n", os.Args[1])
		return
	}

	err := loadGen.ParseArgs()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "failed to parse arguments: %v\n", err)
		fmt.Printf("%s\n", loadGen.Usage())
		os.Exit(1)
	}

	fmt.Printf("Starting %s load generator\n", loadGen.Name())
	loadGen.Run()
}
