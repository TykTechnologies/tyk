//go:build ee || dev

package gateway

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	logrus "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
)

func TestIsWebsocketUpgrade(t *testing.T) {
	type testCase struct {
		name             string
		connectionHeader string
		upgradeHeader    string
		expectedResult   bool
	}

	for _, tc := range []testCase{
		{
			name:             "should be true for capitalized headers",
			connectionHeader: "Upgrade",
			upgradeHeader:    "Websocket",
			expectedResult:   true,
		},
		{
			name:             "should be true for lower-case headers",
			connectionHeader: "upgrade",
			upgradeHeader:    "websocket",
			expectedResult:   true,
		},
		{
			name:             "should be false for wrong connection header",
			connectionHeader: "No-Upgrade",
			upgradeHeader:    "Websocket",
			expectedResult:   false,
		},
		{
			name:             "should be false for wrong upgrade header",
			connectionHeader: "No-Upgrade",
			upgradeHeader:    "Websocket",
			expectedResult:   false,
		},
		{
			name:             "should be false for empty headers",
			connectionHeader: "",
			upgradeHeader:    "",
			expectedResult:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)
			require.NoError(t, err)

			req.Header.Set("Connection", tc.connectionHeader)
			req.Header.Set("Upgrade", tc.upgradeHeader)
			assert.Equal(t, tc.expectedResult, isWebsocketUpgrade(req))
		})
	}
}

func TestDefaultStreamAnalyticsFactory_CreateRecorder(t *testing.T) {
	type testCase struct {
		name                      string
		enableDetailedRecording   bool
		expectedDetailedRecording bool
	}

	t.Run("default recorder", func(t *testing.T) {
		for _, tc := range []testCase{
			{
				name:                      "should create a non-detailed default recorder",
				enableDetailedRecording:   false,
				expectedDetailedRecording: false,
			},
			{
				name:                      "should create a detailed default recorder",
				enableDetailedRecording:   true,
				expectedDetailedRecording: true,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := &APISpec{
					APIDefinition: &apidef.APIDefinition{
						EnableDetailedRecording: tc.enableDetailedRecording,
					},
				}

				req, err := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)
				require.NoError(t, err)

				factory := NewStreamAnalyticsFactory(nil, nil, spec)
				recorder := factory.CreateRecorder(req)

				_, ok := recorder.(*DefaultStreamAnalyticsRecorder)
				assert.True(t, ok)
			})
		}
	})

	t.Run("websocket recorder", func(t *testing.T) {
		for _, tc := range []testCase{
			{
				name:                      "should create a non-detailed websocket recorder",
				enableDetailedRecording:   false,
				expectedDetailedRecording: false,
			},
			{
				name:                      "should create a detailed websocket recorder",
				enableDetailedRecording:   true,
				expectedDetailedRecording: true,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				spec := &APISpec{
					APIDefinition: &apidef.APIDefinition{
						EnableDetailedRecording: tc.enableDetailedRecording,
					},
				}

				req, err := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)
				require.NoError(t, err)

				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")

				factory := NewStreamAnalyticsFactory(nil, nil, spec)
				recorder := factory.CreateRecorder(req)

				websocketRecorder, ok := recorder.(*WebSocketStreamAnalyticsRecorder)
				assert.True(t, ok)
				assert.Equal(t, tc.expectedDetailedRecording, websocketRecorder.Detailed)
			})
		}
	})
}

func TestDefaultStreamAnalyticsRecorder_PrepareRecord(t *testing.T) {
	t.Run("should prepare non-detailed record", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/path", nil)
		require.NoError(t, err)

		recorder := NewDefaultStreamAnalyticsRecorder(nil, &APISpec{APIDefinition: &apidef.APIDefinition{}})
		recorder.PrepareRecord(req)

		assert.NotNil(t, recorder.respCopy)
		assert.NotNil(t, recorder.reqCopy)
		assert.Equal(t, "/path", recorder.reqCopy.URL.Path)
		assert.Equal(t, http.MethodPost, recorder.reqCopy.Method)
	})
}

func TestHandleFuncAdapter_HandleFunc(t *testing.T) {
	logger, _ := logrus.NewNullLogger()
	baseMid := &BaseMiddleware{
		logger: logger.WithContext(context.Background()),
	}
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "test",
			Name:  "test-api",
			IsOAS: true,
		},
	}
	streamSpec := streams.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.StripListenPath)
	streamMiddleware := streams.NewMiddleware(baseMid.Gw, baseMid, streamSpec, nil)

	factory := &testStreamAnalyticsFactory{}
	streamMiddleware.Init()
	streamMiddleware.SetAnalyticsFactory(factory)

	router := mux.NewRouter()
	testHandleFuncAdapter := streams.HandleFuncAdapter{
		StreamID:         "test",
		StreamManager:    streamMiddleware.GetStreamManager(),
		StreamMiddleware: streamMiddleware,
		Muxer:            router,
		Logger:           logger.WithContext(context.Background()),
	}

	testHandleFuncAdapter.HandleFunc("/path", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
		w.Write(nil)
	})

	testServer := httptest.NewServer(router)
	t.Cleanup(testServer.Close)

	targetURL := fmt.Sprintf("%s/%s", testServer.URL, "path")
	req, err := http.NewRequest(http.MethodPost, targetURL, nil)

	client := http.Client{}
	_, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusSwitchingProtocols, factory.responseWriter.responseRecorder.Code)
}

func TestStreamAnalyticsResponseWriter_Write(t *testing.T) {
	logger, _ := logrus.NewNullLogger()
	responseRecorder := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost/path", nil)
	analyticsRecorder := &testStreamAnalyticsRecorder{}

	w := NewStreamAnalyticsResponseWriter(logger.WithContext(context.Background()), responseRecorder, r, "test", analyticsRecorder)
	_, err := w.Write(nil)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, responseRecorder.Code)
	assert.Equal(t, http.StatusOK, analyticsRecorder.actualRecord.ResponseCode)
	assert.Equal(t, "GET", analyticsRecorder.actualRecord.Method)
	assert.Equal(t, "localhost", analyticsRecorder.actualRecord.Host)
	assert.Equal(t, "/path", analyticsRecorder.actualRecord.Path)
}

func TestStreamAnalyticsResponseWriter_WriteHeader(t *testing.T) {
	logger, _ := logrus.NewNullLogger()
	responseRecorder := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost/path", nil)
	analyticsRecorder := &testStreamAnalyticsRecorder{}

	w := NewStreamAnalyticsResponseWriter(logger.WithContext(context.Background()), responseRecorder, r, "test", analyticsRecorder)
	w.WriteHeader(http.StatusSwitchingProtocols)
	assert.Equal(t, http.StatusSwitchingProtocols, responseRecorder.Code)
}

func TestStreamAnalyticsResponseWriter_Hijack(t *testing.T) {
	logger, _ := logrus.NewNullLogger()
	responseRecorder := &testStreamHijackableResponseRecorder{
		responseRecorder: httptest.NewRecorder(),
	}
	r := httptest.NewRequest("GET", "http://localhost/path", nil)
	analyticsRecorder := &testStreamAnalyticsRecorder{}

	w := NewStreamAnalyticsResponseWriter(logger.WithContext(context.Background()), responseRecorder, r, "test", analyticsRecorder)
	_, _, err := w.Hijack()
	require.NoError(t, err)

	assert.Equal(t, http.StatusSwitchingProtocols, analyticsRecorder.actualRecord.ResponseCode)
	assert.Equal(t, "GET", analyticsRecorder.actualRecord.Method)
	assert.Equal(t, "localhost", analyticsRecorder.actualRecord.Host)
	assert.Equal(t, "/path", analyticsRecorder.actualRecord.Path)
}

type testStreamAnalyticsFactory struct {
	recorder       *testStreamAnalyticsRecorder
	responseWriter *testStreamHijackableResponseRecorder
}

func (t *testStreamAnalyticsFactory) CreateRecorder(r *http.Request) streams.StreamAnalyticsRecorder {
	t.recorder = &testStreamAnalyticsRecorder{}
	return t.recorder
}

func (t *testStreamAnalyticsFactory) CreateResponseWriter(w http.ResponseWriter, r *http.Request, streamID string, recorder streams.StreamAnalyticsRecorder) http.ResponseWriter {
	httpRecorder := httptest.NewRecorder()
	t.responseWriter = &testStreamHijackableResponseRecorder{
		responseRecorder: httpRecorder,
	}
	return t.responseWriter
}

type testStreamAnalyticsRecorder struct {
	actualRecord *analytics.AnalyticsRecord
}

func (t *testStreamAnalyticsRecorder) PrepareRecord(r *http.Request) {
	t.actualRecord = &analytics.AnalyticsRecord{
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
	}
	return
}

func (t *testStreamAnalyticsRecorder) RecordHit(statusCode int, latency analytics.Latency) error {
	t.actualRecord.ResponseCode = statusCode
	return nil
}

type testStreamHijackableResponseRecorder struct {
	responseRecorder *httptest.ResponseRecorder
}

func (t *testStreamHijackableResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func (t *testStreamHijackableResponseRecorder) Flush() {
	t.responseRecorder.Flush()
}

func (t *testStreamHijackableResponseRecorder) Header() http.Header {
	return t.responseRecorder.Header()
}

func (t *testStreamHijackableResponseRecorder) Write(i []byte) (int, error) {
	return t.responseRecorder.Write(i)
}

func (t *testStreamHijackableResponseRecorder) WriteHeader(statusCode int) {
	t.responseRecorder.WriteHeader(statusCode)
}
