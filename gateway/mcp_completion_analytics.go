package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/felixge/httpsnoop"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/internal/httpctx"
)

const mcpCompletionObservationLimit = 64 << 10

// mcpCompletionObserver observes enough of a paired MCP response to attribute
// completion to the public API without buffering or delaying the response.
// httpsnoop preserves the exact optional interfaces implemented by the wrapped
// writer, including flushing, hijacking, ReaderFrom, and HTTP/2 push.
type mcpCompletionObserver struct {
	mu     sync.Mutex
	writer http.ResponseWriter
	status int
	body   []byte
}

func observeMCPCompletion(w http.ResponseWriter) (*mcpCompletionObserver, http.ResponseWriter) {
	observer := &mcpCompletionObserver{writer: w}
	wrapped := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) {
				observer.commit(code)
				next(code)
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(data []byte) (int, error) {
				observer.commit(http.StatusOK)
				n, err := next(data)
				observer.append(data[:max(0, min(n, len(data)))])
				return n, err
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(src io.Reader) (int64, error) {
				observer.commit(http.StatusOK)
				return next(io.TeeReader(src, observer))
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				observer.commit(http.StatusOK)
				next()
			}
		},
		Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
			return func() (net.Conn, *bufio.ReadWriter, error) {
				conn, rw, err := next()
				if err == nil {
					observer.commit(http.StatusSwitchingProtocols)
				}
				return conn, rw, err
			}
		},
	})
	return observer, wrapped
}

// Write implements io.Writer for the ReaderFrom observation hook only. The
// bytes have already been sent by the wrapped writer when this is called.
func (o *mcpCompletionObserver) Write(data []byte) (int, error) {
	o.append(data)
	return len(data), nil
}

func (o *mcpCompletionObserver) commit(code int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status == 0 {
		o.status = code
	}
}

func (o *mcpCompletionObserver) append(data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	remaining := mcpCompletionObservationLimit - len(o.body)
	if remaining <= 0 {
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	o.body = append(o.body, data...)
}

func (o *mcpCompletionObserver) snapshot(r *http.Request) (int, []byte, *http.Response) {
	o.mu.Lock()
	defer o.mu.Unlock()
	status := o.status
	if status == 0 {
		status = 499
	}
	body := append([]byte(nil), o.body...)
	response := &http.Response{
		StatusCode:    status,
		Header:        o.writer.Header().Clone(),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}
	return status, body, response
}

type mcpCompletionAnalyticsOwner struct {
	once     sync.Once
	handler  *SuccessHandler
	request  *http.Request
	observer *mcpCompletionObserver
	started  time.Time
}

func newMCPCompletionAnalyticsOwner(handler *SuccessHandler, r *http.Request, w http.ResponseWriter) (*mcpCompletionAnalyticsOwner, http.ResponseWriter) {
	observer, wrapped := observeMCPCompletion(w)
	return &mcpCompletionAnalyticsOwner{
		handler:  handler,
		request:  snapshotMCPAnalyticsRequest(r),
		observer: observer,
		started:  time.Now(),
	}, wrapped
}

func (o *mcpCompletionAnalyticsOwner) Complete(live *http.Request) {
	o.once.Do(func() {
		status, body, response := o.observer.snapshot(o.request)
		if code, ok := jsonRPCCompletionErrorCode(body); ok {
			ctxSetJSONRPCErrorCode(o.request, code)
		} else if code := ctxGetJSONRPCErrorCode(live); code != 0 {
			ctxSetJSONRPCErrorCode(o.request, code)
		}

		total := time.Since(o.started)
		if requestStart := ctxGetRequestStartTime(o.request); !requestStart.IsZero() {
			total = time.Since(requestStart)
		}
		totalMillis := int64(DurationToMillisecond(total))
		o.handler.RecordHit(o.request, analytics.Latency{
			Total:   totalMillis,
			Gateway: totalMillis,
		}, status, response, false)
	})
}

func snapshotMCPAnalyticsRequest(r *http.Request) *http.Request {
	snapshot := r.Clone(r.Context())
	snapshot.Header = r.Header.Clone()
	if r.URL != nil {
		urlCopy := *r.URL
		snapshot.URL = &urlCopy
		if snapshot.URL.Host == "" {
			snapshot.URL.Host = r.Host
		}
	}
	if ingress := httpctx.GetMCPProtocolContext(r); ingress != nil && ingress.RawBody != nil {
		body := append([]byte(nil), ingress.RawBody...)
		snapshot.Body = io.NopCloser(bytes.NewReader(body))
		snapshot.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		snapshot.ContentLength = int64(len(body))
	}
	return snapshot
}

func jsonRPCCompletionErrorCode(body []byte) (int64, bool) {
	if code, ok := jsonRPCErrorCode(body); ok {
		return code, true
	}
	for rest := body; len(rest) > 0; {
		event, _, next, err := parseSSEEvent(rest)
		if err != nil {
			break
		}
		rest = next
		if event == nil || len(event.Data) == 0 {
			continue
		}
		if code, ok := jsonRPCErrorCode([]byte(strings.Join(event.Data, "\n"))); ok {
			return code, true
		}
	}
	return 0, false
}

func jsonRPCErrorCode(data []byte) (int64, bool) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return 0, false
	}
	rawError, ok := envelope["error"]
	if !ok {
		return 0, false
	}
	var rpcError map[string]json.RawMessage
	if err := json.Unmarshal(rawError, &rpcError); err != nil {
		return 0, false
	}
	rawCode, ok := rpcError["code"]
	if !ok {
		return 0, false
	}
	decoder := json.NewDecoder(bytes.NewReader(rawCode))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return 0, false
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	code, err := number.Int64()
	return code, err == nil
}
