package main

import "github.com/TykTechnologies/tyk/pubsub"

var PubSubServer *pubsub.PSServer
var PubSubClient *pubsub.PSClient

func StartPubSubServer() {
	if PubSubServer == nil {
		var err error
		p := config.PubSubServerPort
		if config.PubSubServerPort == "" {
			p = "1211"
		}
		PubSubServer, err = pubsub.NewPSServer(p)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func StartGlobalClient(cs string) {
	PubSubClient = pubsub.NewPSClient()
	if err := PubSubClient.Start(cs); err != nil {
		log.Fatal(err)
	}
}
