package model

import "net/http"

// UpstreamAuthProvider is an interface that can fill in upstream authentication details to the request.
type UpstreamAuthProvider interface {
	Fill(r *http.Request)
}

// MockUpstreamAuthProvider is a mock implementation of UpstreamAuthProvider.
type MockUpstreamAuthProvider struct{}

// Fill is a mock implementation to be used in tests.
func (m *MockUpstreamAuthProvider) Fill(_ *http.Request) {
	// empty mock implementation.
}
