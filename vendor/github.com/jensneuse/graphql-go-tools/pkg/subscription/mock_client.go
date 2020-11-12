package subscription

import (
	"errors"
)

type mockClient struct {
	messagesFromServer []Message
	messageToServer    *Message
	err                error
	messagePipe        chan *Message
	connected          bool
	serverHasRead      bool
}

func newMockClient() *mockClient {
	return &mockClient{
		connected:   true,
		messagePipe: make(chan *Message, 1),
	}
}

func (c *mockClient) ReadFromClient() (*Message, error) {
	returnErr := c.err
	returnMessage := <-c.messagePipe
	if returnErr != nil {
		return nil, returnErr
	}

	c.serverHasRead = true
	c.err = nil
	return returnMessage, returnErr
}

func (c *mockClient) WriteToClient(message Message) error {
	c.messagesFromServer = append(c.messagesFromServer, message)
	return c.err
}

func (c *mockClient) IsConnected() bool {
	return c.connected
}

func (c *mockClient) Disconnect() error {
	c.connected = false
	return nil
}

func (c *mockClient) hasMoreMessagesThan(num int) bool {
	return len(c.messagesFromServer) > num
}

func (c *mockClient) readFromServer() []Message {
	return c.messagesFromServer
}

func (c *mockClient) prepareConnectionInitMessage() *mockClient {
	c.messageToServer = &Message{
		Type: MessageTypeConnectionInit,
	}

	return c
}

func (c *mockClient) prepareStartMessage(id string, payload []byte) *mockClient {
	c.messageToServer = &Message{
		Id:      id,
		Type:    MessageTypeStart,
		Payload: payload,
	}

	return c
}

func (c *mockClient) prepareStopMessage(id string) *mockClient {
	c.messageToServer = &Message{
		Id:      id,
		Type:    MessageTypeStop,
		Payload: nil,
	}

	return c
}

func (c *mockClient) prepareConnectionTerminateMessage() *mockClient {
	c.messageToServer = &Message{
		Type: MessageTypeConnectionTerminate,
	}

	return c
}

func (c *mockClient) send() bool {
	c.messagePipe <- c.messageToServer
	c.messageToServer = nil
	return true
}

func (c *mockClient) withoutError() *mockClient {
	c.err = nil
	return c
}

func (c *mockClient) withError() *mockClient {
	c.err = errors.New("error")
	return c
}

func (c *mockClient) and() *mockClient {
	return c
}

func (c *mockClient) reset() *mockClient {
	c.messagesFromServer = []Message{}
	return c
}

func (c *mockClient) reconnect() *mockClient {
	c.reset()
	c.connected = true
	return c
}
