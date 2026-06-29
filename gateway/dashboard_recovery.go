package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	dashboardSyncReadErrorMaxAttempts     = 2
	dashboardControlPlaneRetryMaxAttempts = 8
)

const (
	dashboardControlPlaneRetryCodeBusy    = "control_plane_busy"
	dashboardControlPlaneRetryCodeWarming = "control_plane_warming"
)

var dashboardSyncSleep = func(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// DashboardAuthError represents a non-nonce authentication failure
type DashboardAuthError struct {
	StatusCode int
	Body       string
}

func (e *DashboardAuthError) Error() string {
	return fmt.Sprintf("dashboard authentication failed (status %d): %s", e.StatusCode, e.Body)
}

type dashboardControlPlaneError struct {
	Status            string                    `json:"Status"`
	Message           string                    `json:"Message"`
	Code              string                    `json:"code"`
	RetryAfterSeconds int                       `json:"retry_after_seconds"`
	Meta              dashboardControlPlaneMeta `json:"Meta"`
}

type dashboardControlPlaneMeta struct {
	Code              string `json:"code"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
	Generation        uint64 `json:"generation"`
}

// executeDashboardRequestWithRecovery performs a dashboard request with automatic recovery for network and nonce errors.
// It uses a 2-attempt policy (original + 1 retry) to avoid unbounded recursion.
// The buildReq function should create a fresh request with updated headers (including nonce).
func (gw *Gateway) executeDashboardRequestWithRecovery(buildReq func() (*http.Request, error), errorContext string) (*http.Response, error) {
	const maxAttempts = 2

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Build fresh request with current nonce
		req, err := buildReq()
		if err != nil {
			return nil, fmt.Errorf("failed to build request: %w", err)
		}

		// Execute request
		c := gw.initialiseClient()
		resp, err := c.Do(req)

		// Handle network errors during request
		if err != nil {
			if attempt < maxAttempts && shouldRetryOnNetworkError(err) && gw.DashService != nil {
				log.WithField("context", errorContext).Warning("Network error detected, attempting to re-register node...")
				if recoveryErr := gw.attemptDashboardRecovery(); recoveryErr != nil {
					log.WithField("context", errorContext).Error("Failed to re-register node after network error: ", recoveryErr)
					return nil, err // Return original error
				}
				log.WithField("context", errorContext).Info("Node re-registered successfully, retrying request...")
				continue // Retry with fresh nonce
			}
			return nil, err
		}

		// Handle forbidden responses (potential nonce issues)
		if resp.StatusCode == http.StatusForbidden {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				body = []byte("failed to read response body")
			}
			resp.Body.Close()
			errorMessage := string(body)

			if attempt < maxAttempts && isNonceRelatedError(errorMessage) && gw.DashService != nil {
				log.WithField("context", errorContext).Warning("Dashboard nonce failure detected, attempting to re-register node...")
				if recoveryErr := gw.attemptDashboardRecovery(); recoveryErr != nil {
					log.WithField("context", errorContext).Error("Failed to re-register node during recovery: ", recoveryErr)
					return nil, &DashboardAuthError{StatusCode: resp.StatusCode, Body: errorMessage}
				}
				log.WithField("context", errorContext).Info("Node re-registered successfully, retrying request...")
				continue // Retry with fresh nonce
			}

			// Non-nonce auth failure or final attempt
			log.WithField("context", errorContext).Warning("Dashboard authentication failed: ", errorMessage)
			// Re-wrap body so caller can still read it if needed
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, nil // Let caller handle non-403 or decide on error mapping
		}

		// Success or non-403 error
		return resp, nil
	}

	// Should never reach here due to loop structure
	return nil, errors.New("max retry attempts exceeded")
}

// HandleDashboardResponseReadError checks if a read/decode error is recoverable (EOF-related)
// and attempts recovery if appropriate. Returns true if the caller should retry the entire operation.
func (gw *Gateway) HandleDashboardResponseReadError(err error, errorContext string) bool {
	if err == nil || gw.DashService == nil {
		return false
	}

	if isEOFError(err) {
		log.WithField("context", errorContext).Warning("Network error detected while reading response, attempting to re-register node...")
		if recoveryErr := gw.attemptDashboardRecovery(); recoveryErr != nil {
			log.WithField("context", errorContext).Error("Failed to re-register node after read error: ", recoveryErr)
			return false
		}
		log.WithField("context", errorContext).Info("Node re-registered successfully after read error")
		return true // Caller should retry
	}

	return false
}

func dashboardSyncRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}

	delay := time.Second * time.Duration(1<<(attempt-1))
	if delay > 8*time.Second {
		delay = 8 * time.Second
	}

	jitter := time.Duration(rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(int64(500 * time.Millisecond)))
	return delay + jitter
}

// HandleDashboardRetryableControlPlaneResponse retries typed dashboard control-plane backpressure responses.
func (gw *Gateway) HandleDashboardRetryableControlPlaneResponse(resp *http.Response, body []byte, attempt, maxAttempts int, errorContext string) (bool, error) {
	retry, ok := parseDashboardRetryableControlPlaneResponse(resp, body)
	if !ok {
		return false, nil
	}
	if attempt >= maxAttempts {
		log.WithFields(logrus.Fields{
			"context": errorContext,
			"code":    retry.Meta.Code,
			"attempt": attempt,
			"max":     maxAttempts,
		}).Warn("Dashboard control-plane retry exhausted")
		return false, nil
	}

	delay := dashboardControlPlaneRetryDelay(resp, retry, attempt)
	log.WithFields(logrus.Fields{
		"context":       errorContext,
		"code":          retry.Meta.Code,
		"generation":    retry.Meta.Generation,
		"attempt":       attempt,
		"max":           maxAttempts,
		"retry_wait_ms": delay.Milliseconds(),
	}).Warn("Dashboard control-plane response is retryable; retrying sync without re-register")

	if !gw.sleepDashboardSyncRetry(delay) {
		return true, gw.dashboardSyncContextErr()
	}
	return true, nil
}

func parseDashboardRetryableControlPlaneResponse(resp *http.Response, body []byte) (dashboardControlPlaneError, bool) {
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable || len(body) == 0 {
		return dashboardControlPlaneError{}, false
	}

	var errResp dashboardControlPlaneError
	if err := json.Unmarshal(body, &errResp); err != nil {
		return dashboardControlPlaneError{}, false
	}

	if errResp.Meta.Code == "" {
		errResp.Meta.Code = errResp.Code
	}
	if errResp.Meta.RetryAfterSeconds == 0 {
		errResp.Meta.RetryAfterSeconds = errResp.RetryAfterSeconds
	}

	switch errResp.Meta.Code {
	case dashboardControlPlaneRetryCodeBusy, dashboardControlPlaneRetryCodeWarming:
		return errResp, true
	default:
		return dashboardControlPlaneError{}, false
	}
}

func dashboardControlPlaneRetryDelay(resp *http.Response, errResp dashboardControlPlaneError, attempt int) time.Duration {
	delay := retryAfterHeaderDelay(resp.Header.Get("Retry-After"))
	if delay <= 0 && errResp.Meta.RetryAfterSeconds > 0 {
		delay = time.Duration(errResp.Meta.RetryAfterSeconds) * time.Second
	}
	if delay <= 0 {
		delay = dashboardSyncRetryDelay(attempt)
	}

	const maxControlPlaneRetryDelay = 10 * time.Second
	if delay > maxControlPlaneRetryDelay {
		delay = maxControlPlaneRetryDelay
	}

	jitter := time.Duration(rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(int64(500 * time.Millisecond)))
	return delay + jitter
}

func retryAfterHeaderDelay(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	delay := time.Until(retryAt)
	if delay <= 0 {
		return 0
	}
	return delay
}

func (gw *Gateway) sleepDashboardSyncRetry(delay time.Duration) bool {
	ctx := context.Background()
	if gw != nil && gw.ctx != nil {
		ctx = gw.ctx
	}
	return dashboardSyncSleep(ctx, delay)
}

func (gw *Gateway) dashboardSyncContextErr() error {
	if gw != nil && gw.ctx != nil && gw.ctx.Err() != nil {
		return gw.ctx.Err()
	}
	return context.Canceled
}

func (gw *Gateway) setServiceNonceIfPresent(source, nonce string) bool {
	if nonce == "" {
		log.WithField("source", source).Warn("Dashboard response missing nonce; keeping existing nonce")
		return false
	}

	gw.ServiceNonceMutex.Lock()
	gw.ServiceNonce = nonce
	gw.ServiceNonceMutex.Unlock()
	return true
}

// attemptDashboardRecovery attempts to re-register the node with the dashboard.
// It uses gw.ctx so that recovery is cancelled when the Gateway receives a shutdown
// signal (SIGTERM/SIGINT), preventing goroutines from blocking indefinitely.
func (gw *Gateway) attemptDashboardRecovery() error {
	if gw.DashService == nil {
		return errors.New("dashboard service not available for recovery")
	}

	return gw.DashService.Register(gw.ctx)
}

// shouldRetryOnNetworkError checks if an error is a network error that might benefit from retry
func shouldRetryOnNetworkError(err error) bool {
	if err == nil {
		return false
	}
	// Check for EOF errors first (common during connection drops)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "network is unreachable")
}

// isNonceRelatedError checks if an error message indicates a nonce synchronization issue
func isNonceRelatedError(errorMessage string) bool {
	return strings.Contains(errorMessage, "Nonce failed") ||
		strings.Contains(errorMessage, "nonce") ||
		strings.Contains(errorMessage, "No node ID Found")
}

// isEOFError checks if an error is an EOF-related error
func isEOFError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(err.Error(), "EOF")
}
