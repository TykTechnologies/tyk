package subscription

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

const (
	MessageTypeConnectionInit      = "connection_init"
	MessageTypeConnectionAck       = "connection_ack"
	MessageTypeConnectionError     = "connection_error"
	MessageTypeConnectionTerminate = "connection_terminate"
	MessageTypeConnectionKeepAlive = "ka"
	MessageTypeStart               = "start"
	MessageTypeStop                = "stop"
	MessageTypeData                = "data"
	MessageTypeError               = "error"
	MessageTypeComplete            = "complete"

	DefaultKeepAliveInterval          = "15s"
	DefaultSubscriptionUpdateInterval = "1s"
)

// Message defines the actual subscription message wich will be passed from client to server and vice versa.
type Message struct {
	Id      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// client provides an interface which can be implemented by any possible subscription client like websockets, mqtt, etc.
type Client interface {
	// ReadFromClient will invoke a read operation from the client connection.
	ReadFromClient() (*Message, error)
	// WriteToClient will invoke a write operation to the client connection.
	WriteToClient(Message) error
	// IsConnected will indicate if a connection is still established.
	IsConnected() bool
	// Disconnect will close the connection between server and client.
	Disconnect() error
}

// ExecutorPool is an abstraction for creating executors
type ExecutorPool interface {
	Get(payload []byte) (Executor, error)
	Put(executor Executor) error
}

// Executor is an abstraction for executing a GraphQL engine
type Executor interface {
	Execute(writer resolve.FlushWriter) error
	OperationType() ast.OperationType
	SetContext(context context.Context)
	Reset()
}

// Handler is the actual subscription handler which will keep track on how to handle messages coming from the client.
type Handler struct {
	logger abstractlogger.Logger
	// client will hold the subscription client implementation.
	client Client
	// keepAliveInterval is the actual interval on which the server send keep alive messages to the client.
	keepAliveInterval time.Duration
	// subscriptionUpdateInterval is the actual interval on which the server sends subscription updates to the client.
	subscriptionUpdateInterval time.Duration
	// subCancellations is map containing the cancellation functions to every active subscription.
	subCancellations subscriptionCancellations
	// executorPool is responsible to create and hold executors.
	executorPool ExecutorPool
	// bufferPool will hold buffers.
	bufferPool *sync.Pool
}

// NewHandler creates a new subscription handler.
func NewHandler(logger abstractlogger.Logger, client Client, executorPool ExecutorPool) (*Handler, error) {
	keepAliveInterval, err := time.ParseDuration(DefaultKeepAliveInterval)
	if err != nil {
		return nil, err
	}

	subscriptionUpdateInterval, err := time.ParseDuration(DefaultSubscriptionUpdateInterval)
	if err != nil {
		return nil, err
	}

	return &Handler{
		logger:                     logger,
		client:                     client,
		keepAliveInterval:          keepAliveInterval,
		subscriptionUpdateInterval: subscriptionUpdateInterval,
		subCancellations:           subscriptionCancellations{},
		executorPool:               executorPool,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				writer := graphql.NewEngineResultWriterFromBuffer(bytes.NewBuffer(make([]byte, 0, 1024)))
				return &writer
			},
		},
	}, nil
}

// Handle will handle the subscription connection.
func (h *Handler) Handle(ctx context.Context) {
	defer func() {
		h.subCancellations.CancelAll()
	}()

	for {
		if !h.client.IsConnected() {
			h.logger.Debug("subscription.Handler.Handle()",
				abstractlogger.String("message", "client has disconnected"),
			)

			return
		}

		message, err := h.client.ReadFromClient()
		if err != nil {
			h.logger.Error("subscription.Handler.Handle()",
				abstractlogger.Error(err),
				abstractlogger.Any("message", message),
			)

			h.handleConnectionError("could not read message from client")
		} else if message != nil {
			switch message.Type {
			case MessageTypeConnectionInit:
				h.handleInit()
				go h.handleKeepAlive(ctx)
			case MessageTypeStart:
				h.handleStart(message.Id, message.Payload)
			case MessageTypeStop:
				h.handleStop(message.Id)
			case MessageTypeConnectionTerminate:
				h.handleConnectionTerminate()
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
			continue
		}
	}
}

// ChangeKeepAliveInterval can be used to change the keep alive interval.
func (h *Handler) ChangeKeepAliveInterval(d time.Duration) {
	h.keepAliveInterval = d
}

// ChangeSubscriptionUpdateInterval can be used to change the update interval.
func (h *Handler) ChangeSubscriptionUpdateInterval(d time.Duration) {
	h.subscriptionUpdateInterval = d
}

// handleInit will handle an init message.
func (h *Handler) handleInit() {
	ackMessage := Message{
		Type: MessageTypeConnectionAck,
	}

	err := h.client.WriteToClient(ackMessage)
	if err != nil {
		h.logger.Error("subscription.Handler.handleInit()",
			abstractlogger.Error(err),
		)
	}
}

// handleStart will handle s start message.
func (h *Handler) handleStart(id string, payload []byte) {
	executor, err := h.executorPool.Get(payload)
	if err != nil {
		h.logger.Error("subscription.Handler.handleStart()",
			abstractlogger.Error(err),
		)

		h.handleError(id, graphql.RequestErrorsFromError(err))
		return
	}

	if err = h.handleOnBeforeStart(executor); err != nil {
		h.handleError(id, graphql.RequestErrorsFromError(err))
		return
	}

	if executor.OperationType() == ast.OperationTypeSubscription {
		ctx := h.subCancellations.Add(id)
		go h.startSubscription(ctx, id, executor)
		return
	}

	go h.handleNonSubscriptionOperation(id, executor)
}

func (h *Handler) handleOnBeforeStart(executor Executor) error {
	switch e := executor.(type) {
	case *ExecutorV2:
		if hook := e.engine.GetWebsocketBeforeStartHook(); hook != nil {
			return hook.OnBeforeStart(e.reqCtx, e.operation)
		}
	case *ExecutorV1:
		// do nothing
	}

	return nil
}

// handleNonSubscriptionOperation will handle a non-subscription operation like a query or a mutation.
func (h *Handler) handleNonSubscriptionOperation(id string, executor Executor) {
	defer func() {
		err := h.executorPool.Put(executor)
		if err != nil {
			h.logger.Error("subscription.Handle.handleNonSubscriptionOperation()",
				abstractlogger.Error(err),
			)
		}
	}()

	buf := h.bufferPool.Get().(*graphql.EngineResultWriter)
	buf.Reset()

	defer h.bufferPool.Put(buf)

	// err := executor.Execute(executionContext, node, buf)
	err := executor.Execute(buf)
	if err != nil {
		h.logger.Error("subscription.Handle.handleNonSubscriptionOperation()",
			abstractlogger.Error(err),
		)

		h.handleError(id, graphql.RequestErrorsFromError(err))
		return
	}

	h.logger.Debug("subscription.Handle.handleNonSubscriptionOperation()",
		abstractlogger.ByteString("execution_result", buf.Bytes()),
	)

	h.sendData(id, buf.Bytes())
	h.sendComplete(id)
}

// startSubscription will invoke the actual subscription.
func (h *Handler) startSubscription(ctx context.Context, id string, executor Executor) {
	defer func() {
		err := h.executorPool.Put(executor)
		if err != nil {
			h.logger.Error("subscription.Handle.startSubscription()",
				abstractlogger.Error(err),
			)
		}
	}()

	executor.SetContext(ctx)
	buf := h.bufferPool.Get().(*graphql.EngineResultWriter)
	buf.Reset()

	defer h.bufferPool.Put(buf)

	h.executeSubscription(buf, id, executor)

	for {
		buf.Reset()
		select {
		case <-ctx.Done():
			return
		case <-time.After(h.subscriptionUpdateInterval):
			h.executeSubscription(buf, id, executor)
		}
	}

}

// executeSubscription will keep execution the subscription until it ends.
func (h *Handler) executeSubscription(buf *graphql.EngineResultWriter, id string, executor Executor) {
	buf.SetFlushCallback(func(data []byte) {
		h.logger.Debug("subscription.Handle.executeSubscription()",
			abstractlogger.ByteString("execution_result", data),
		)
		h.sendData(id, data)
	})
	defer buf.SetFlushCallback(nil)

	err := executor.Execute(buf)
	if err != nil {
		h.logger.Error("subscription.Handle.executeSubscription()",
			abstractlogger.Error(err),
		)

		h.handleError(id, graphql.RequestErrorsFromError(err))
		return
	}

	if buf.Len() > 0 {
		data := buf.Bytes()
		h.logger.Debug("subscription.Handle.executeSubscription()",
			abstractlogger.ByteString("execution_result", data),
		)
		h.sendData(id, data)
	}
}

// handleStop will handle a stop message,
func (h *Handler) handleStop(id string) {
	h.subCancellations.Cancel(id)
	h.sendComplete(id)
}

// sendData will send a data message to the client.
func (h *Handler) sendData(id string, responseData []byte) {
	dataMessage := Message{
		Id:      id,
		Type:    MessageTypeData,
		Payload: responseData,
	}

	err := h.client.WriteToClient(dataMessage)
	if err != nil {
		h.logger.Error("subscription.Handler.sendData()",
			abstractlogger.Error(err),
		)
	}
}

// nolint
// sendComplete will send a complete message to the client.
func (h *Handler) sendComplete(id string) {
	completeMessage := Message{
		Id:      id,
		Type:    MessageTypeComplete,
		Payload: nil,
	}

	err := h.client.WriteToClient(completeMessage)
	if err != nil {
		h.logger.Error("subscription.Handler.sendComplete()",
			abstractlogger.Error(err),
		)
	}
}

// handleConnectionTerminate will handle a comnnection terminate message.
func (h *Handler) handleConnectionTerminate() {
	err := h.client.Disconnect()
	if err != nil {
		h.logger.Error("subscription.Handler.handleConnectionTerminate()",
			abstractlogger.Error(err),
		)
	}
}

// handleKeepAlive will handle the keep alive loop.
func (h *Handler) handleKeepAlive(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(h.keepAliveInterval):
			h.sendKeepAlive()
		}
	}
}

// sendKeepAlive will send a keep alive message to the client.
func (h *Handler) sendKeepAlive() {
	keepAliveMessage := Message{
		Type: MessageTypeConnectionKeepAlive,
	}

	err := h.client.WriteToClient(keepAliveMessage)
	if err != nil {
		h.logger.Error("subscription.Handler.sendKeepAlive()",
			abstractlogger.Error(err),
		)
	}
}

// handleConnectionError will handle a connection error message.
func (h *Handler) handleConnectionError(errorPayload interface{}) {
	payloadBytes, err := json.Marshal(errorPayload)
	if err != nil {
		h.logger.Error("subscription.Handler.handleConnectionError()",
			abstractlogger.Error(err),
			abstractlogger.Any("errorPayload", errorPayload),
		)
	}

	connectionErrorMessage := Message{
		Type:    MessageTypeConnectionError,
		Payload: payloadBytes,
	}

	err = h.client.WriteToClient(connectionErrorMessage)
	if err != nil {
		h.logger.Error("subscription.Handler.handleConnectionError()",
			abstractlogger.Error(err),
		)

		err := h.client.Disconnect()
		if err != nil {
			h.logger.Error("subscription.Handler.handleError()",
				abstractlogger.Error(err),
			)
		}
	}
}

// handleError will handle an error message.
func (h *Handler) handleError(id string, errors graphql.RequestErrors) {
	payloadBytes, err := json.Marshal(errors)
	if err != nil {
		h.logger.Error("subscription.Handler.handleError()",
			abstractlogger.Error(err),
			abstractlogger.Any("errors", errors),
		)
	}

	errorMessage := Message{
		Id:      id,
		Type:    MessageTypeError,
		Payload: payloadBytes,
	}

	err = h.client.WriteToClient(errorMessage)
	if err != nil {
		h.logger.Error("subscription.Handler.handleError()",
			abstractlogger.Error(err),
		)
	}
}

// ActiveSubscriptions will return the actual number of active subscriptions for that client.
func (h *Handler) ActiveSubscriptions() int {
	return len(h.subCancellations)
}
