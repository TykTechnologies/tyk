package gateway

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/user"
)

// ResponseErrorOverrideMiddleware intercepts upstream 4xx/5xx responses
// and applies configured error overrides before they reach the client.
type ResponseErrorOverrideMiddleware struct {
	BaseTykResponseHandler
}

func (r *ResponseErrorOverrideMiddleware) Base() *BaseTykResponseHandler {
	return &r.BaseTykResponseHandler
}

func (r *ResponseErrorOverrideMiddleware) Name() string {
	return "ResponseErrorOverrideMiddleware"
}

func (r *ResponseErrorOverrideMiddleware) Enabled() bool {
	// Fast path: check config before any processing
	return len(r.Spec.GlobalConfig.ErrorOverrides) > 0
}

func (r *ResponseErrorOverrideMiddleware) Init(c interface{}, spec *APISpec) error {
	r.Spec = spec
	return nil
}

func (r *ResponseErrorOverrideMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
	//no-op: this middleware only handles upstream responses, not errors in the gateway itself
}

func (r *ResponseErrorOverrideMiddleware) HandleResponse(
	rw http.ResponseWriter,
	res *http.Response,
	req *http.Request,
	ses *user.SessionState,
) error {
	if !r.shouldProcessResponse(res) {
		return nil
	}

	defer res.Body.Close()

	logger := r.logger().WithFields(logrus.Fields{
		"prefix": "error-override",
		"api_id": r.Spec.APIID,
	})

	bodyReader := newLazyBodyReader(res.Body, logger)
	overrides := NewErrorOverrides(r.Spec, r.Gw)
	result := overrides.ApplyUpstreamOverride(res.StatusCode, bodyReader.Read)

	if result == nil {
		bodyReader.RestoreIfRead(res)
		return nil
	}

	logger.Debug("Applying upstream error override")
	r.applyOverrideToResponse(res, result, req, logger)
	bodyReader.RestoreIfRead(res)

	return nil
}

// shouldProcessResponse checks if response should be processed for error overrides.
func (r *ResponseErrorOverrideMiddleware) shouldProcessResponse(res *http.Response) bool {
	return res.StatusCode >= 400 && len(r.Spec.GlobalConfig.ErrorOverrides) > 0
}

// lazyBodyReader handles lazy reading and caching of response body.
type lazyBodyReader struct {
	body   io.ReadCloser
	data   []byte
	read   bool
	logger *logrus.Entry
}

func newLazyBodyReader(body io.ReadCloser, logger *logrus.Entry) *lazyBodyReader {
	return &lazyBodyReader{body: body, logger: logger}
}

func (l *lazyBodyReader) Read() []byte {
	if !l.read {
		var err error
		l.data, err = io.ReadAll(io.LimitReader(l.body, maxBodySizeForMatching))
		if err != nil {
			l.logger.WithError(err).Error("Failed to read response body for matching")
			return nil
		}
		l.read = true
	}
	return l.data
}

func (l *lazyBodyReader) RestoreIfRead(res *http.Response) {
	if l.read {
		res.Body = io.NopCloser(bytes.NewReader(l.data))
	}
}

// applyOverrideToResponse applies the override result to the HTTP response.
func (r *ResponseErrorOverrideMiddleware) applyOverrideToResponse(
	res *http.Response,
	result *OverrideResult,
	req *http.Request,
	logger *logrus.Entry,
) {
	if result.Code > 0 {
		res.StatusCode = result.Code
	}

	for key, value := range result.Headers {
		res.Header.Set(key, value)
	}

	if !r.hasBodyConfig(result) {
		return
	}

	errCtx := DetectErrorResponseContext(req)
	newBody := r.generateOverrideBody(result, errCtx, res.StatusCode, logger)
	if newBody != nil {
		res.Body = io.NopCloser(bytes.NewReader(newBody))
		res.ContentLength = int64(len(newBody))
		res.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		res.Header.Set("Content-Type", errCtx.ContentType)
	}
}

// hasBodyConfig returns true if the override has body configuration.
func (r *ResponseErrorOverrideMiddleware) hasBodyConfig(result *OverrideResult) bool {
	return result.GetBody() != "" ||
		result.rule.Response.Template != "" ||
		result.GetMessageForTemplate() != ""
}

func (r *ResponseErrorOverrideMiddleware) generateOverrideBody(
	result *OverrideResult,
	errCtx *ErrorResponseContext,
	statusCode int,
	logger *logrus.Entry,
) []byte {
	if tmplExecutor := result.GetTemplateExecutor(r.Gw, errCtx); tmplExecutor != nil {
		var buf bytes.Buffer
		data := &APIErrorWithContext{
			StatusCode: statusCode,
			Message:    result.GetMessageForTemplate(),
		}
		if err := tmplExecutor.Execute(&buf, data); err != nil {
			logger.WithError(err).Error("Failed to apply error override template")
			return nil
		}
		return buf.Bytes()
	}

	if body := result.GetBody(); body != "" {
		return []byte(body)
	}

	return nil
}
