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
	return len(r.Spec.GlobalConfig.ErrorOverrides) > 0 ||
		len(r.Spec.ErrorOverrides) > 0
}

func (r *ResponseErrorOverrideMiddleware) Init(_ any, spec *APISpec) error {
	r.Spec = spec
	return nil
}

func (r *ResponseErrorOverrideMiddleware) HandleError(_ http.ResponseWriter, _ *http.Request) {
	//no-op: this middleware only handles upstream responses, not errors in the gateway itself
}

func (r *ResponseErrorOverrideMiddleware) HandleResponse(
	_ http.ResponseWriter,
	res *http.Response,
	req *http.Request,
	_ *user.SessionState,
) error {

	if !r.shouldProcessResponse(res) {
		return nil
	}

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
	bodyReplaced := r.applyOverrideToResponse(res, result, req, logger)
	if !bodyReplaced {
		logger.Debug("Override body generation failed or not configured, using original upstream body")
		bodyReader.RestoreIfRead(res)
	} else {
		// Body was replaced with override, close the original body as we won't need it
		bodyReader.CloseOriginal()
	}

	return nil
}

// shouldProcessResponse checks if response should be processed for error overrides.
func (r *ResponseErrorOverrideMiddleware) shouldProcessResponse(res *http.Response) bool {
	return res.StatusCode >= 400 &&
		(len(r.Spec.GlobalConfig.ErrorOverrides) > 0 || (!r.Spec.ErrorOverridesDisabled && len(r.Spec.ErrorOverrides) > 0))
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
		// Combine the data we already read with the remainder of the original body stream.
		// This prevents data loss for responses larger than maxBodySizeForMatching.
		res.Body = io.NopCloser(io.MultiReader(bytes.NewReader(l.data), l.body))
	}
}

func (l *lazyBodyReader) CloseOriginal() {
	if l.body != nil {
		l.body.Close()
	}
}

// applyOverrideToResponse applies the override result to the HTTP response.
// Returns true if the response body was successfully replaced, false otherwise.
func (r *ResponseErrorOverrideMiddleware) applyOverrideToResponse(
	res *http.Response,
	result *OverrideResult,
	req *http.Request,
	logger *logrus.Entry,
) bool {

	if result.StatusCode > 0 {
		res.StatusCode = result.StatusCode
	}

	bodyReplaced := false

	if r.hasBodyConfig(result) {
		errCtx := DetectErrorResponseContext(req)
		newBody := r.generateOverrideBody(result, errCtx, res.StatusCode, logger)
		if newBody != nil {
			res.Body = io.NopCloser(bytes.NewReader(newBody))
			res.ContentLength = int64(len(newBody))
			res.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
			res.Header.Set("Content-Type", errCtx.ContentType)
			bodyReplaced = true
		}
	}

	for key, value := range result.Headers {
		res.Header.Set(key, value)
	}

	return bodyReplaced
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
	// Check for inline template (body with {{.}} variables) or file template
	if tmplExecutor := result.GetTemplateExecutor(r.Gw, errCtx); tmplExecutor != nil {
		return r.executeTemplate(tmplExecutor, result.GetMessageForTemplate(), statusCode, errCtx.IsXML, logger)
	}

	// Direct body (no template variables)
	if body := result.GetBody(); body != "" {
		return []byte(body)
	}

	// Message only - use default Tyk error template (like gateway errors do)
	if result.ShouldUseDefaultTemplate() {
		return r.generateDefaultTemplateBody(result, errCtx, statusCode, logger)
	}

	return nil
}

// generateDefaultTemplateBody generates response using Tyk's default error template.
// This matches the behavior of gateway-generated errors when only message is configured.
func (r *ResponseErrorOverrideMiddleware) generateDefaultTemplateBody(
	result *OverrideResult,
	errCtx *ErrorResponseContext,
	statusCode int,
	logger *logrus.Entry,
) []byte {

	templateName := "error." + errCtx.TemplateExtension

	var tmpl TemplateExecutor
	if errCtx.IsXML {
		tmpl = r.Gw.templatesRaw.Lookup(templateName)
	} else {
		tmpl = r.Gw.templates.Lookup(templateName)
	}

	if tmpl == nil {
		logger.WithField("template", templateName).Warn("Default error template not found")
		return nil
	}

	return r.executeTemplate(tmpl, result.GetMessageForTemplate(), statusCode, errCtx.IsXML, logger)
}

// executeTemplate is a helper that executes a template with the given message and status code.
func (r *ResponseErrorOverrideMiddleware) executeTemplate(
	tmpl TemplateExecutor,
	message string,
	statusCode int,
	isXML bool,
	logger *logrus.Entry,
) []byte {
	var buf bytes.Buffer
	data := &APIErrorWithContext{
		StatusCode: statusCode,
		Message:    escapeTemplateString(message, isXML),
	}

	if err := tmpl.Execute(&buf, data); err != nil {
		logger.WithError(err).Error("Failed to execute error template")
		return nil
	}

	return buf.Bytes()
}
