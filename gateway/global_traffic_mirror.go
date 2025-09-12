package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GlobalTrafficMirrorMiddleware implements global traffic mirroring
type GlobalTrafficMirrorMiddleware struct {
	*GlobalBaseMiddleware
	configData map[string]interface{}
	client *http.Client
}

// Name returns the middleware name
func (g *GlobalTrafficMirrorMiddleware) Name() string {
	return "GlobalTrafficMirrorMiddleware"
}

// EnabledForSpec always returns true for global middleware
func (g *GlobalTrafficMirrorMiddleware) EnabledForSpec() bool {
	return true
}

// Base returns the base middleware
func (g *GlobalTrafficMirrorMiddleware) Base() *BaseMiddleware {
	return g.GlobalBaseMiddleware.BaseMiddleware
}

// GetSpec returns the API spec
func (g *GlobalTrafficMirrorMiddleware) GetSpec() *APISpec {
	return g.GlobalBaseMiddleware.BaseMiddleware.Spec
}

// Config returns the middleware configuration
func (g *GlobalTrafficMirrorMiddleware) Config() (interface{}, error) {
	return g.configData, nil
}

// Init initializes the global traffic mirror middleware
func (g *GlobalTrafficMirrorMiddleware) Init() {
	g.GlobalBaseMiddleware.BaseMiddleware.Init()
	
	// Initialize HTTP client with configurable timeout
	timeout := g.GetConfigInt("timeout")
	if timeout == 0 {
		timeout = 5 // Default 5 seconds
	}
	
	g.client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// ProcessRequest processes the request and mirrors it globally
func (g *GlobalTrafficMirrorMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Check if this request should be sampled
	sampleRate := g.GetConfigFloat("sample_rate")
	if sampleRate > 0 && rand.Float64() > sampleRate {
		return nil, http.StatusOK
	}
	
	// Get destinations configuration
	destinations := g.getDestinations()
	if len(destinations) == 0 {
		return nil, http.StatusOK
	}
	
	// Clone the request for mirroring
	mirrorReq, err := g.cloneRequest(r)
	if err != nil {
		g.Logger().WithError(err).Error("Failed to clone request for global mirroring")
		return nil, http.StatusOK
	}
	
	// Check if this should be async
	async := g.GetConfigBool("async")
	if async {
		// Send mirrors asynchronously
		go g.sendMirrors(mirrorReq, destinations)
	} else {
		// Send mirrors synchronously
		g.sendMirrors(mirrorReq, destinations)
	}
	
	return nil, http.StatusOK
}

// GlobalMirrorDestination represents a destination for global mirroring
type GlobalMirrorDestination struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout int               `json:"timeout"`
}

// getDestinations parses destinations from config
func (g *GlobalTrafficMirrorMiddleware) getDestinations() []GlobalMirrorDestination {
	destinations := []GlobalMirrorDestination{}
	
	destConfig, exists := g.GetConfigValue("destinations")
	if !exists {
		return destinations
	}
	
	destSlice, ok := destConfig.([]interface{})
	if !ok {
		return destinations
	}
	
	for _, item := range destSlice {
		destMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		
		dest := GlobalMirrorDestination{
			Headers: make(map[string]string),
		}
		
		if url, ok := destMap["url"].(string); ok {
			dest.URL = url
		}
		
		if timeout, ok := destMap["timeout"].(float64); ok {
			dest.Timeout = int(timeout)
		}
		
		if headers, ok := destMap["headers"].(map[string]interface{}); ok {
			for k, v := range headers {
				if str, ok := v.(string); ok {
					dest.Headers[k] = str
				}
			}
		}
		
		if dest.URL != "" {
			destinations = append(destinations, dest)
		}
	}
	
	return destinations
}

// cloneRequest creates a deep copy of the HTTP request
func (g *GlobalTrafficMirrorMiddleware) cloneRequest(r *http.Request) (*http.Request, error) {
	// Read the body
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		// Restore the original request body
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Create new request
	clonedReq := &http.Request{
		Method:        r.Method,
		URL:          &url.URL{},
		Proto:        r.Proto,
		ProtoMajor:   r.ProtoMajor,
		ProtoMinor:   r.ProtoMinor,
		Header:       make(http.Header),
		ContentLength: r.ContentLength,
		Host:         r.Host,
		RemoteAddr:   r.RemoteAddr,
		RequestURI:   r.RequestURI,
	}

	// Deep copy URL
	*clonedReq.URL = *r.URL
	if r.URL.User != nil {
		clonedReq.URL.User = &url.Userinfo{}
		*clonedReq.URL.User = *r.URL.User
	}

	// Deep copy headers
	for k, v := range r.Header {
		clonedReq.Header[k] = make([]string, len(v))
		copy(clonedReq.Header[k], v)
	}

	// Set body if exists
	if len(bodyBytes) > 0 {
		clonedReq.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return clonedReq, nil
}

// sendMirrors sends the request to all configured mirror destinations
func (g *GlobalTrafficMirrorMiddleware) sendMirrors(r *http.Request, destinations []GlobalMirrorDestination) {
	var wg sync.WaitGroup
	
	for _, dest := range destinations {
		wg.Add(1)
		go func(destination GlobalMirrorDestination) {
			defer wg.Done()
			g.sendSingleMirror(r, destination)
		}(dest)
	}
	
	wg.Wait()
}

// sendSingleMirror sends request to a single mirror destination
func (g *GlobalTrafficMirrorMiddleware) sendSingleMirror(r *http.Request, dest GlobalMirrorDestination) {
	// Clone the request for this destination
	mirrorReq, err := g.cloneRequest(r)
	if err != nil {
		g.Logger().WithError(err).Error("Failed to clone request for global mirror destination")
		return
	}

	// Parse destination URL
	destURL, err := url.Parse(dest.URL)
	if err != nil {
		g.Logger().WithError(err).WithField("url", dest.URL).Error("Invalid global mirror destination URL")
		return
	}

	// Update request URL to point to mirror destination
	mirrorReq.URL.Scheme = destURL.Scheme
	mirrorReq.URL.Host = destURL.Host
	
	// Preserve the original path unless destination has a path
	if destURL.Path != "" && destURL.Path != "/" {
		mirrorReq.URL.Path = strings.TrimSuffix(destURL.Path, "/") + "/" + strings.TrimPrefix(mirrorReq.URL.Path, "/")
	}

	// Set destination host
	mirrorReq.Host = destURL.Host

	// Add global headers from config
	globalHeaders := g.GetConfigMap("headers")
	for k, v := range globalHeaders {
		if str, ok := v.(string); ok {
			mirrorReq.Header.Set(k, str)
		}
	}

	// Add destination-specific headers
	for k, v := range dest.Headers {
		mirrorReq.Header.Set(k, v)
	}

	// Add global mirroring metadata headers
	mirrorReq.Header.Set("X-Tyk-Global-Mirror", "true")
	mirrorReq.Header.Set("X-Tyk-Global-Mirror-Source", r.Host)
	mirrorReq.Header.Set("X-Tyk-Global-Mirror-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	
	// Add API ID if available
	if g.BaseMiddleware != nil && g.BaseMiddleware.Spec != nil {
		mirrorReq.Header.Set("X-Tyk-Global-Mirror-API-ID", g.BaseMiddleware.Spec.APIID)
	}

	// Create client with destination-specific timeout
	client := g.client
	timeout := 5 * time.Second // Default timeout
	
	if g.client != nil {
		timeout = g.client.Timeout
	}
	
	if dest.Timeout > 0 {
		timeout = time.Duration(dest.Timeout) * time.Second
		if g.client != nil {
			client = &http.Client{
				Timeout:   timeout,
				Transport: g.client.Transport,
			}
		} else {
			client = &http.Client{Timeout: timeout}
		}
	} else if g.client == nil {
		client = &http.Client{Timeout: timeout}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	mirrorReq = mirrorReq.WithContext(ctx)

	// Send the mirrored request
	resp, err := client.Do(mirrorReq)
	if err != nil {
		g.Logger().WithError(err).
			WithField("destination", dest.URL).
			Debug("Failed to send global mirrored request")
		return
	}
	defer resp.Body.Close()

	// Log successful mirror (debug level to avoid spam)
	g.Logger().WithField("destination", dest.URL).
		WithField("status", resp.StatusCode).
		Debug("Successfully sent global mirrored request")

	// Drain response body to allow connection reuse
	io.Copy(io.Discard, resp.Body)
}

// Unload cleans up resources
func (g *GlobalTrafficMirrorMiddleware) Unload() {
	if g.client != nil && g.client.Transport != nil {
		if transport, ok := g.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}