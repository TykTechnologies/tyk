package storage

import (
	"context"

	"github.com/TykTechnologies/tyk/api"
	"github.com/go-redis/redis/v8"
)

var _ Notify = (*nativeNotify)(nil)

// nativeNotify implements Notify interface by using api.PubSubClient
type nativeNotify struct {
	client api.PubSubClient
}

// Publish sends a publish request to a remove pubsub server
func (n *nativeNotify) Publish(channel, message string) error {
	if n.client == nil {
		return nil
	}
	_, err := n.client.Publish(context.Background(), &api.PublishRequest{
		Channel: channel,
		Message: message,
	})
	return err
}

// StartPubSubHandler streams messages from the PubSub server and executes
// callback on every message received. The value passed to callback is of type
// *redis.message.
func (n *nativeNotify) StartPubSubHandler(channel string, callback func(interface{})) error {
	if n.client == nil {
		return nil
	}
	stream, err := n.client.Subscribe(context.Background(), &api.SubscribeRequest{
		Channel: channel,
	})
	if err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if callback != nil {
			callback(&redis.Message{
				Channel:      msg.Channel,
				Pattern:      msg.Pattern,
				Payload:      msg.Payload,
				PayloadSlice: msg.PayloadSlice,
			})
		}
	}
}
