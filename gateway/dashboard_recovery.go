package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DashboardAuthError represents a non-nonce authentication failure
type DashboardAuthError struct {
	StatusCode int
	Body       string
}

func (e *DashboardAuthError) Error() string {
	return fmt.Sprintf("dashboard authentication failed (status %d): %s", e.StatusCode, e.Body)
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

// attemptDashboardRecovery attempts to re-register the node with the dashboard
func (gw *Gateway) attemptDashboardRecovery() error {
	if gw.DashService == nil {
		return errors.New("dashboard service not available for recovery")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return gw.DashService.Register(ctx)
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