package gateway

import (
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "io/ioutil"
    "net/http"
    "time"

    "github.com/TykTechnologies/tyk-pump/analytics"
    "github.com/TykTechnologies/tyk/apidef"
    "github.com/TykTechnologies/tyk/internal/middleware"

    awsconfig "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/lambda"
    lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// AWSLambdaMiddleware invokes AWS Lambda functions for matching endpoints.
type AWSLambdaMiddleware struct {
    *BaseMiddleware

    sh SuccessHandler
}

func (m *AWSLambdaMiddleware) Name() string { return "AWSLambda" }

func (m *AWSLambdaMiddleware) Init() { m.sh = SuccessHandler{m.BaseMiddleware} }

func (m *AWSLambdaMiddleware) EnabledForSpec() bool {
    // Enabled if any version has a non-disabled AWSLambda entry
    for _, v := range m.Spec.VersionData.Versions {
        for _, l := range v.ExtendedPaths.AWSLambda {
            if !l.Disabled {
                return true
            }
        }
    }
    return false
}

func (m *AWSLambdaMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
    vInfo, status := m.Spec.Version(r)
    if status != StatusOk {
        return nil, http.StatusOK
    }

    versionPaths := m.Spec.RxPaths[vInfo.Name]
    found, meta := m.Spec.CheckSpecMatchesStatus(r, versionPaths, AWSLambda)
    if !found {
        return nil, http.StatusOK
    }
    cfg := meta.(*apidef.AWSLambdaMeta)

    // Prepare context with timeout
    timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
    if timeout <= 0 {
        // Convert seconds to duration; default to 30s if unset
        sec := m.Spec.GlobalConfig.ProxyDefaultTimeout
        if sec <= 0 {
            sec = 30
        }
        timeout = time.Duration(sec * float64(time.Second))
    }
    ctx, cancel := context.WithTimeout(r.Context(), timeout)
    defer cancel()

    // Build payload
    payload, err := m.buildLambdaPayload(r, cfg)
    if err != nil {
        return fmt.Errorf("failed to build lambda payload: %w", err), http.StatusInternalServerError
    }

    // Invoke
    start := time.Now()
    out, reqID, fnErr, invokeErr := m.invokeLambda(ctx, cfg, payload)
    ms := DurationToMillisecond(time.Since(start))
    if invokeErr != nil {
        m.Logger().WithError(invokeErr).Error("Lambda invoke failed")
        return errors.New("upstream Lambda invocation error"), http.StatusBadGateway
    }

    // Map response
    res, statusCode, mapErr := m.mapLambdaResponse(r, out, cfg, fnErr, reqID)
    if mapErr != nil {
        m.Logger().WithError(mapErr).Error("Lambda response mapping failed")
        return errors.New("lambda response mapping error"), http.StatusBadGateway
    }

    // Run response chain then write
    if _, err := handleResponseChain(m.Spec.ResponseChain, w, res, r, ctxGetSession(r)); err != nil {
        m.Logger().WithError(err).Error("Response chain failed for Lambda result")
        return errors.New("response chain failed"), http.StatusBadGateway
    }

    m.Gw.handleForcedResponse(w, res, ctxGetSession(r), m.Spec)

    // Record analytics (2xx only by SuccessHandler)
    m.sh.RecordHit(r, analytics.Latency{Total: int64(ms)}, statusCode, res, false)

    return nil, middleware.StatusRespond
}

// buildLambdaPayload builds the Lambda request payload using proxy integration by default.
func (m *AWSLambdaMiddleware) buildLambdaPayload(r *http.Request, cfg *apidef.AWSLambdaMeta) ([]byte, error) {
    mapping := cfg.RequestMapping

    // Read body
    var bodyBytes []byte
    if r.Body != nil {
        b, err := ioutil.ReadAll(r.Body)
        if err != nil {
            return nil, err
        }
        bodyBytes = b
        // Reset so later middlewares (if any) could read, though we respond here
        r.Body = ioutil.NopCloser(bytes.NewReader(b))
    }

    // Default to proxy_integration mapping
    if mapping.Mode == "" || mapping.Mode == "proxy_integration" {
        type proxyReq struct {
            Resource                        string                        `json:"resource,omitempty"`
            Path                            string                        `json:"path"`
            HttpMethod                      string                        `json:"httpMethod"`
            Headers                         map[string]string             `json:"headers,omitempty"`
            MultiValueHeaders               map[string][]string           `json:"multiValueHeaders,omitempty"`
            QueryStringParameters           map[string]string             `json:"queryStringParameters,omitempty"`
            MultiValueQueryStringParameters map[string][]string           `json:"multiValueQueryStringParameters,omitempty"`
            PathParameters                  map[string]string             `json:"pathParameters,omitempty"`
            StageVariables                  map[string]string             `json:"stageVariables,omitempty"`
            Body                            string                        `json:"body"`
            IsBase64Encoded                 bool                          `json:"isBase64Encoded"`
        }

        // Path as seen by upstream
        path := r.URL.Path
        if mapping.ForwardPath {
            path = m.Spec.StripListenPath(path)
        }

        // Headers
        singleHeaders := map[string]string{}
        multiHeaders := map[string][]string{}
        if mapping.ForwardHeaders || !mapping.ForwardHeaders { // default: forward all
            for k, v := range r.Header {
                multiHeaders[k] = v
                if len(v) > 0 {
                    singleHeaders[k] = v[0]
                }
            }
        }

        // Query params
        singleQuery := map[string]string{}
        multiQuery := map[string][]string{}
        if mapping.ForwardQuerystring || !mapping.ForwardQuerystring { // default true
            q := r.URL.Query()
            for k, v := range q {
                multiQuery[k] = v
                if len(v) > 0 {
                    singleQuery[k] = v[0]
                }
            }
        }

        // Body
        isB64 := false
        var bodyStr string
        if mapping.ForwardBody || !mapping.ForwardBody { // default true
            if mapping.Base64EncodeBody {
                bodyStr = base64.StdEncoding.EncodeToString(bodyBytes)
                isB64 = true
            } else {
                bodyStr = string(bodyBytes)
            }
        }

        req := proxyReq{
            Path:                            path,
            HttpMethod:                      r.Method,
            Headers:                         singleHeaders,
            MultiValueHeaders:               multiHeaders,
            QueryStringParameters:           singleQuery,
            MultiValueQueryStringParameters: multiQuery,
            Body:                            bodyStr,
            IsBase64Encoded:                 isB64,
        }
        return json.Marshal(req)
    }

    // passthrough: send raw body
    if mapping.Mode == "passthrough" {
        return bodyBytes, nil
    }

    // template mode not implemented in first version
    return nil, fmt.Errorf("unsupported request mapping mode: %s", mapping.Mode)
}

func (m *AWSLambdaMiddleware) invokeLambda(ctx context.Context, cfg *apidef.AWSLambdaMeta, payload []byte) (*lambda.InvokeOutput, string, string, error) {
    // Load AWS config
    awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
    if err != nil {
        return nil, "", "", err
    }

    var client *lambda.Client
    if cfg.Credentials.EndpointOverride != "" {
        // For LocalStack/testing
        endpoint := cfg.Credentials.EndpointOverride
        client = lambda.NewFromConfig(awsCfg, func(o *lambda.Options) {
            o.BaseEndpoint = &endpoint
        })
    } else {
        client = lambda.NewFromConfig(awsCfg)
    }

    invType := lambdatypes.InvocationTypeRequestResponse
    switch cfg.InvocationType {
    case "Event":
        invType = lambdatypes.InvocationTypeEvent
    case "DryRun":
        invType = lambdatypes.InvocationTypeDryRun
    }

    out, err := client.Invoke(ctx, &lambda.InvokeInput{
        FunctionName:  &cfg.FunctionName,
        Payload:       payload,
        InvocationType: invType,
        Qualifier:     nilIfEmpty(cfg.Qualifier),
    })
    reqID := ""
    fnErr := ""
    if out != nil && out.FunctionError != nil {
        fnErr = *out.FunctionError
    }
    return out, reqID, fnErr, err
}

func (m *AWSLambdaMiddleware) mapLambdaResponse(r *http.Request, out *lambda.InvokeOutput, cfg *apidef.AWSLambdaMeta, functionError string, requestID string) (*http.Response, int, error) {
    res := &http.Response{Header: make(http.Header)}
    res.Proto = r.Proto
    res.ProtoMajor = r.ProtoMajor
    res.ProtoMinor = r.ProtoMinor
    res.Request = r

    // Handle async (Event) or DryRun
    if out == nil || cfg.InvocationType == "Event" || cfg.InvocationType == "DryRun" {
        res.StatusCode = http.StatusAccepted
        res.Body = io.NopCloser(bytes.NewReader(nil))
        return res, res.StatusCode, nil
    }

    // Function platform error
    if functionError != "" {
        status := cfg.ResponseMapping.UnhandledStatus
        if status == 0 {
            status = http.StatusBadGateway
        }
        res.StatusCode = status
        if requestID != "" {
            res.Header.Set("X-Amzn-RequestId", requestID)
        }
        res.Header.Set("X-Amz-Function-Error", functionError)
        res.Body = io.NopCloser(bytes.NewReader(out.Payload))
        res.ContentLength = int64(len(out.Payload))
        return res, res.StatusCode, nil
    }

    // Response mapping
    mapping := cfg.ResponseMapping
    if mapping.Mode == "" || mapping.Mode == "proxy_integration" {
        type proxyRes struct {
            StatusCode      int                 `json:"statusCode"`
            Headers         map[string]string  `json:"headers"`
            MultiValueHeaders map[string][]string `json:"multiValueHeaders"`
            Body            string              `json:"body"`
            IsBase64Encoded bool                `json:"isBase64Encoded"`
        }
        var pr proxyRes
        if err := json.Unmarshal(out.Payload, &pr); err != nil {
            // Not a proxy response; fall back to raw
            mapping.Mode = "raw"
        } else {
            if pr.StatusCode == 0 {
                pr.StatusCode = mapping.DefaultStatus
                if pr.StatusCode == 0 {
                    pr.StatusCode = http.StatusOK
                }
            }
            // Headers
            ignoreCanonical := m.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
            for k, v := range pr.Headers {
                setCustomHeader(res.Header, k, v, ignoreCanonical)
            }
            for k, vv := range pr.MultiValueHeaders {
                setCustomHeaderMultipleValues(res.Header, k, vv, ignoreCanonical)
            }
            // Body
            var body []byte
            if pr.IsBase64Encoded || mapping.DecodeBase64Body {
                decoded, err := base64.StdEncoding.DecodeString(pr.Body)
                if err == nil {
                    body = decoded
                } else {
                    body = []byte(pr.Body)
                }
            } else {
                body = []byte(pr.Body)
            }
            res.StatusCode = pr.StatusCode
            res.Body = io.NopCloser(bytes.NewReader(body))
            res.ContentLength = int64(len(body))
            return res, res.StatusCode, nil
        }
    }

    // Raw mode: pass payload through
    if mapping.Mode == "raw" {
        status := mapping.DefaultStatus
        if status == 0 {
            status = http.StatusOK
        }
        res.StatusCode = status
        res.Body = io.NopCloser(bytes.NewReader(out.Payload))
        res.ContentLength = int64(len(out.Payload))
        return res, res.StatusCode, nil
    }

    return nil, 0, fmt.Errorf("unsupported response mapping mode: %s", mapping.Mode)
}

func nilIfEmpty(s string) *string {
    if s == "" {
        return nil
    }
    return &s
}
