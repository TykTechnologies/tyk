package pubsub

import (
	"github.com/TykTechnologies/tyk-cluster-framework/client"
	"github.com/TykTechnologies/tyk-cluster-framework/server"
	"fmt"
	"github.com/TykTechnologies/tyk-cluster-framework/encoding"
	"errors"
	"github.com/TykTechnologies/tyk-cluster-framework/payloads"
)

type PSServer struct{
	server server.Server
}

type PSClient struct{
	client client.Client
	isConnected bool
	handlerPool map[string]client.PayloadHandler
}

func NewPSClient() *PSClient {
	pc := &PSClient{}
	pc.handlerPool = make(map[string]client.PayloadHandler)
	return pc
}

func NewPSServer(onPort string) (*PSServer, error) {
	cs := fmt.Sprintf("mangos://127.0.0.1:%v", onPort)
	s, err := server.NewServer(cs, encoding.JSON)
	if err != nil {
		return nil, err
	}

	pss := PSServer{
		server: s,
	}

	return &pss, nil
}

func (c *PSClient) Start(cs string) error {
	if c.client != nil && c.isConnected {
		err := c.Stop()
		if err != nil {
			return err
		}
	}

	// Create a new client from scratch because we might be reconnecting
	mc, err := client.NewClient(cs, encoding.JSON)
	if err != nil {
		return err
	}

	c.client = mc
	err = c.client.Connect()
	if err != nil {
		return err
	}

	c.isConnected = true

	// Initialise the subscriptions in case we are reconnecting
	for t, h := range c.handlerPool {
		_, err := c.client.Subscribe(t, h)
		if err == nil {
			return err
		}
	}

	return nil
}

func (c *PSClient) Stop() error {
	err := c.client.Stop()
	if err != nil {
		return err
	}
	c.isConnected = false
	return nil
}

func (c *PSClient) Subscribe(topic string, handler client.PayloadHandler) error {
	_, f := c.handlerPool[topic]
	if f {
		// Error, already set
		return errors.New("Topic already has a handler!")
	}

	// Add it to our pool for later and do the sub
	c.handlerPool[topic] = handler
	if c.isConnected {
		// We are connected, so we should now actually do the sub
		_, err := c.client.Subscribe(topic, handler)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *PSClient) Publish(filter string, payload payloads.Payload) error {
	if !c.isConnected || c.client == nil {
		// TODO: should we queue them?
		return errors.New("Client is not connected!")
	}

	return c.client.Publish(filter, payload)
}

func OnLeaderChange(newLeader string) error {
	return nil
}

//func (s *PSServer) Start() error {
//
//}
//
//func (s *PSServer) Stop() error {
//
//}

