package apidef

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reqproofRoundTripFunc func(*http.Request) (*http.Response, error)

func (f reqproofRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// Verifies: SYS-REQ-104, SW-REQ-086
// SW-REQ-086:nominal:nominal
// SW-REQ-086:boundary:boundary
// SW-REQ-086:error_handling:negative
// SW-REQ-086:determinism:nominal
func TestNotificationsReqProof_ClientAndSuccessfulSend(t *testing.T) {
	t.Run("default notification client has bounded dial, TLS, and request timeouts", func(t *testing.T) {
		client := initHttpNotificationClient()
		require.NotNil(t, client)
		assert.Equal(t, 10*time.Second, client.Timeout)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.Equal(t, 5*time.Second, transport.TLSHandshakeTimeout)
		require.NotNil(t, transport.Dial)
	})

	t.Run("configured manager sends JSON POST with fixed headers", func(t *testing.T) {
		requests := 0
		var captured struct {
			Method       string
			UserAgent    string
			ContentType  string
			SharedSecret string
			Body         map[string]string
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			captured.Method = r.Method
			captured.UserAgent = r.Header.Get("User-Agent")
			captured.ContentType = r.Header.Get("Content-Type")
			captured.SharedSecret = r.Header.Get("X-Tyk-Shared-Secret")
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured.Body))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`ok`))
		}))
		defer server.Close()

		restoreNotificationClient(t, server.Client())

		manager := NotificationsManager{
			SharedSecret:      "shared-secret",
			OAuthKeyChangeURL: server.URL,
		}

		manager.SendRequest(false, 0, map[string]string{"event": "key-change"})

		assert.Equal(t, 1, requests)
		assert.Equal(t, http.MethodPost, captured.Method)
		assert.Equal(t, "Tyk-Gatewy-Notifications", captured.UserAgent)
		assert.Equal(t, "application/json", captured.ContentType)
		assert.Equal(t, "shared-secret", captured.SharedSecret)
		assert.Equal(t, map[string]string{"event": "key-change"}, captured.Body)
	})
}

// Verifies: SYS-REQ-104, SW-REQ-086
// SW-REQ-086:nominal:nominal
// SW-REQ-086:boundary:boundary
// SW-REQ-086:error_handling:negative
// SW-REQ-086:determinism:nominal
func TestNotificationsReqProof_ErrorAndBoundaryPaths(t *testing.T) {
	t.Run("empty URL returns without using the HTTP client", func(t *testing.T) {
		called := false
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected")
		})})

		NotificationsManager{}.SendRequest(false, 0, map[string]string{"event": "ignored"})

		assert.False(t, called)
	})

	t.Run("retry limit returns before marshaling or using the HTTP client", func(t *testing.T) {
		called := false
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected")
		})})

		NotificationsManager{OAuthKeyChangeURL: "http://example.invalid"}.SendRequest(true, 3, map[string]string{"event": "ignored"})

		assert.False(t, called)
	})

	t.Run("marshal errors return without using the HTTP client", func(t *testing.T) {
		called := false
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected")
		})})

		NotificationsManager{OAuthKeyChangeURL: "http://example.invalid"}.SendRequest(false, 0, make(chan int))

		assert.False(t, called)
	})

	t.Run("invalid request URL returns without using the HTTP client", func(t *testing.T) {
		called := false
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected")
		})})

		NotificationsManager{OAuthKeyChangeURL: "://bad-url"}.SendRequest(false, 0, map[string]string{"event": "ignored"})

		assert.False(t, called)
	})

	t.Run("terminal HTTP retry attempt performs one request and returns on network error", func(t *testing.T) {
		calls := 0
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("network failure")
		})})

		NotificationsManager{OAuthKeyChangeURL: "http://example.invalid"}.SendRequest(false, 2, map[string]string{"event": "retry"})

		assert.Equal(t, 1, calls)
	})

	t.Run("terminal HTTP retry attempt returns on response body read error", func(t *testing.T) {
		calls := 0
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(reqproofErrorReader{}),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})})

		NotificationsManager{OAuthKeyChangeURL: "http://example.invalid"}.SendRequest(false, 2, map[string]string{"event": "retry"})

		assert.Equal(t, 1, calls)
	})

	t.Run("terminal HTTP retry attempt returns on non-200 status", func(t *testing.T) {
		calls := 0
		restoreNotificationClient(t, &http.Client{Transport: reqproofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusAccepted,
				Body:       io.NopCloser(reqproofStringReader("accepted")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})})

		NotificationsManager{OAuthKeyChangeURL: "http://example.invalid"}.SendRequest(false, 2, map[string]string{"event": "retry"})

		assert.Equal(t, 1, calls)
	})
}

func restoreNotificationClient(t *testing.T, client *http.Client) {
	t.Helper()

	original := httpClient
	httpClient = client
	t.Cleanup(func() {
		httpClient = original
	})
}

type reqproofErrorReader struct{}

func (reqproofErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure")
}

type reqproofStringReader string

func (r reqproofStringReader) Read(p []byte) (int, error) {
	if len(r) == 0 {
		return 0, io.EOF
	}
	n := copy(p, string(r))
	return n, io.EOF
}
