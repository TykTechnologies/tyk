package http

import (
	"context"
	"encoding/json"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/subscription"
)

// WebsocketSubscriptionClient is an actual implementation of the subscritpion client interface.
type WebsocketSubscriptionClient struct {
	logger abstractlogger.Logger
	// clientConn holds the actual connection to the client.
	clientConn net.Conn
	// isClosedConnection indicates if the websocket connection is closed.
	isClosedConnection bool
}

// NewWebsocketSubscriptionClient will create a new websocket subscription client.
func NewWebsocketSubscriptionClient(logger abstractlogger.Logger, clientConn net.Conn) *WebsocketSubscriptionClient {
	return &WebsocketSubscriptionClient{
		logger:     logger,
		clientConn: clientConn,
	}
}

// ReadFromClient will read a subscription message from the websocket client.
func (w *WebsocketSubscriptionClient) ReadFromClient() (message *subscription.Message, err error) {
	var data []byte
	var opCode ws.OpCode

	data, opCode, err = wsutil.ReadClientData(w.clientConn)
	if err != nil {
		if w.isClosedConnectionError(err) {
			return message, nil
		}

		w.logger.Error("http.WebsocketSubscriptionClient.ReadFromClient()",
			abstractlogger.Error(err),
			abstractlogger.ByteString("data", data),
			abstractlogger.Any("opCode", opCode),
		)

		w.isClosedConnectionError(err)

		return nil, err
	}

	err = json.Unmarshal(data, &message)
	if err != nil {
		w.logger.Error("http.WebsocketSubscriptionClient.ReadFromClient()",
			abstractlogger.Error(err),
			abstractlogger.ByteString("data", data),
			abstractlogger.Any("opCode", opCode),
		)

		return nil, err
	}

	return message, nil
}

// WriteToClient will write a subscription message to the websocket client.
func (w *WebsocketSubscriptionClient) WriteToClient(message subscription.Message) error {
	if w.isClosedConnection {
		return nil
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		w.logger.Error("http.WebsocketSubscriptionClient.WriteToClient()",
			abstractlogger.Error(err),
			abstractlogger.Any("message", message),
		)

		return err
	}

	err = wsutil.WriteServerMessage(w.clientConn, ws.OpText, messageBytes)
	if err != nil {
		w.logger.Error("http.WebsocketSubscriptionClient.WriteToClient()",
			abstractlogger.Error(err),
			abstractlogger.ByteString("messageBytes", messageBytes),
		)

		return err
	}

	return nil
}

// IsConnected will indicate if the websocket conenction is still established.
func (w *WebsocketSubscriptionClient) IsConnected() bool {
	return !w.isClosedConnection
}

// Disconnect will close the websocket connection.
func (w *WebsocketSubscriptionClient) Disconnect() error {
	w.logger.Debug("http.GraphQLHTTPRequestHandler.Disconnect()",
		abstractlogger.String("message", "disconnecting client"),
	)
	w.isClosedConnection = true
	return w.clientConn.Close()
}

// isClosedConnectionError will indicate if the given error is a conenction closed error.
func (w *WebsocketSubscriptionClient) isClosedConnectionError(err error) bool {
	if _, ok := err.(wsutil.ClosedError); ok {
		w.isClosedConnection = true
	}

	return w.isClosedConnection
}

func HandleWebsocket(done chan bool, errChan chan error, conn net.Conn, executorPool subscription.ExecutorPool, logger abstractlogger.Logger) {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("http.HandleWebsocket()",
				abstractlogger.String("message", "could not close connection to client"),
				abstractlogger.Error(err),
			)
		}
	}()

	websocketClient := NewWebsocketSubscriptionClient(logger, conn)
	subscriptionHandler, err := subscription.NewHandler(logger, websocketClient, executorPool)
	if err != nil {
		logger.Error("http.HandleWebsocket()",
			abstractlogger.String("message", "could not create subscriptionHandler"),
			abstractlogger.Error(err),
		)

		errChan <- err
		return
	}

	close(done)
	subscriptionHandler.Handle(context.Background()) // Blocking
}

// handleWebsocket will handle the websocket connection.
func (g *GraphQLHTTPRequestHandler) handleWebsocket(conn net.Conn) {
	done := make(chan bool)
	errChan := make(chan error)

	executorPool := subscription.NewExecutorV1Pool(g.executionHandler)
	go HandleWebsocket(done, errChan, conn, executorPool, g.log)
	select {
	case err := <-errChan:
		g.log.Error("http.GraphQLHTTPRequestHandler.handleWebsocket()",
			abstractlogger.Error(err),
		)
	case <-done:
	}
}
