package streamshadow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"

	"github.com/warpstreamlabs/bento/public/service"
)

type StreamMiddlewareWrapper interface {
	Unwrap() StreamManagerCreator
}

type StreamManagerCreator interface {
	CreateStreamManager(r *http.Request) *streams.Manager
}

type MiddlewareMetadataGetter interface {
	GetMiddlewareMetadata(r *http.Request, mode apidef.URLStatus) (interface{}, bool)
}

type ApiSpecGetter interface {
	GetApiSpec(apiID string) interface{}
}

type GetStreamingMW interface {
	GetStreamingMW() model.Middleware
}

// NewMiddleware returns a new instance of Middleware.
func NewMiddleware(gw streams.Gateway, mwGetter MiddlewareMetadataGetter, spec *apidef.APIDefinition, logger *logrus.Entry) *Middleware {
	return &Middleware{
		Gw:       gw,
		mwGetter: mwGetter,
		logger:   logger,
	}
}

// Middleware implements response middleware for streamShadow.
type Middleware struct {
	mwGetter MiddlewareMetadataGetter
	Spec     *apidef.APIDefinition
	Gw       streams.Gateway
	logger   *logrus.Entry
}

// Name returns the name of the middleware.
func (h *Middleware) Name() string {
	return "StreamShadowResponseMiddleware"
}

// Init initializes the middleware.
func (h *Middleware) Init(config interface{}, spec *apidef.APIDefinition) error {
	h.Spec = spec
	return nil
}

// HandleResponse logs request and response JSON payloads.
func (h *Middleware) HandleResponse(w http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	meta, found := h.mwGetter.GetMiddlewareMetadata(req, apidef.StreamShadow)

	if !found {
		return nil
	}

	config, ok := meta.(*apidef.StreamShadowMeta)
	if !ok {
		h.logger.Error("Invalid stream shadow configuration")
		return nil
	}
	h.logger.WithFields(logrus.Fields{
		"path_regex":     config.Method,
		"method":         config.Path,
		"streamId":       config.StreamId,
		"streamingApiId": config.StreamingApiId,
		"request_method": req.Method,
		"request_path":   req.URL.Path,
	}).Debug("Stream shadow configuration")

	var stream *streams.Stream
	if apiSpecGetter, ok := h.Gw.(ApiSpecGetter); ok {
		if apiSpec := apiSpecGetter.GetApiSpec(config.StreamingApiId); apiSpec != nil {
			if streamingMWGetter, ok := apiSpec.(GetStreamingMW); ok {
				if streamingMW := streamingMWGetter.GetStreamingMW(); streamingMW != nil {
					if streamingMW, ok := streamingMW.(*streams.Middleware); ok {
						streamManager := streamingMW.CreateStreamManager(req)
						if streamManager != nil {
							stream, _ = streamManager.GetStream(config.StreamId)
						}
					}
				}
			}
		}
	}

	if stream == nil {
		h.logger.WithFields(logrus.Fields{
			"streamId":       config.StreamId,
			"streamingApiId": config.StreamingApiId,
		}).Error("Stream not found in the given API")
		return nil
	}

	// Prepare combined request and response data
	combinedData := map[string]interface{}{
		"request": map[string]interface{}{
			"method":  req.Method,
			"url":     req.URL.String(),
			"headers": req.Header,
		},
		"response": map[string]interface{}{
			"status":     res.Status,
			"statusCode": res.StatusCode,
			"headers":    res.Header,
		},
	}

	// Handle request body
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			h.logger.WithError(err).Error("Failed to read request body")
		} else {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			combinedData["request"].(map[string]interface{})["body"] = string(bodyBytes)
		}
	}

	// Handle response body
	if res.Body != nil {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			h.logger.WithError(err).Error("Failed to read response body")
		} else {
			res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			combinedData["response"].(map[string]interface{})["body"] = string(bodyBytes)
		}
	}

	// Serialize combined data
	jsonPayload, err := json.Marshal(combinedData)
	if err != nil {
		h.logger.WithError(err).Error("Failed to serialize combined request and response data")
		return nil
	}

	// Produce to stream in a goroutine
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		err := stream.Produce(ctx, jsonPayload)
		if err != nil {
			h.logger.WithError(err).Error("Given Stream is not shadow_stream")
		} else {
			h.logger.WithFields(logrus.Fields{
				"streamId":       config.StreamId,
				"streamingApiId": config.StreamingApiId,
			}).Info("Stream shadow message produced")
		}
	}()

	return nil
}

// HandleError handles any errors that occur during response processing.
func (h *Middleware) HandleError(rw http.ResponseWriter, req *http.Request) {
	// noop
}

// Enabled checks if the middleware is enabled.
func (h *Middleware) Enabled() bool {
	for _, version := range h.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.StreamShadow) > 0 {
			return true
		}
	}
	return false
}

// streamShadowInputConfigSpec returns an empty ConfigSpec for the stream shadow input.
func streamShadowInputConfigSpec() *service.ConfigSpec {
	return service.NewConfigSpec().
		Summary("Receives messages from a stream shadow source.").
		Description("This input plugin receives messages from a stream shadow source without performing any actions.")
}

func init() {
	err := service.RegisterBatchInput(
		"stream_shadow",
		streamShadowInputConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.BatchInput, error) {
			return &streamShadowInput{}, nil
		},
	)
	if err != nil {
		panic(err)
	}
}

type streamShadowInput struct{}

func (s *streamShadowInput) Connect(ctx context.Context) error {
	return nil
}

func (s *streamShadowInput) ReadBatch(ctx context.Context) (service.MessageBatch, service.AckFunc, error) {
	return nil, func(context.Context, error) error { return nil }, nil
}

func (s *streamShadowInput) Close(ctx context.Context) error {
	return nil
}
