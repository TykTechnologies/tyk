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

	"github.com/TykTechnologies/tyk/apidef"
)

// TrafficMirrorMiddleware mirrors incoming requests to configured destinations
type TrafficMirrorMiddleware struct {
	*BaseMiddleware
	client *http.Client
}


func (t *TrafficMirrorMiddleware) Name() string {
	return "TrafficMirrorMiddleware"
}

func (t *TrafficMirrorMiddleware) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TrafficMirror) > 0 {
			return true
		}
	}
	return false
}

func (t *TrafficMirrorMiddleware) Init() {
	t.BaseMiddleware.Init()
	// Initialize HTTP client with reasonable defaults
	t.client = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

func (t *TrafficMirrorMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, _ := t.Spec.Version(r)
	versionPaths := t.Spec.RxPaths[vInfo.Name]
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, TrafficMirrored)
	
	if !found {
		return nil, http.StatusOK
	}

	mirrorSpec, ok := meta.(*apidef.TrafficMirrorMeta)
	if !ok {
		t.Logger().Error("Invalid mirror specification")
		return nil, http.StatusOK
	}

	// Check global sample rate first
	if mirrorSpec.SampleRate > 0 && rand.Float64() > mirrorSpec.SampleRate {
		return nil, http.StatusOK
	}

	// Clone the request for mirroring
	mirrorReq, err := t.cloneRequest(r)
	if err != nil {
		t.Logger().WithError(err).Error("Failed to clone request for mirroring")
		return nil, http.StatusOK
	}

	if mirrorSpec.Async {
		// Send mirrors asynchronously
		go t.sendMirrors(mirrorReq, mirrorSpec)
	} else {
		// Send mirrors synchronously (blocks main request)
		t.sendMirrors(mirrorReq, mirrorSpec)
	}

	return nil, http.StatusOK
}

// cloneRequest creates a deep copy of the HTTP request
func (t *TrafficMirrorMiddleware) cloneRequest(r *http.Request) (*http.Request, error) {
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
func (t *TrafficMirrorMiddleware) sendMirrors(r *http.Request, spec *apidef.TrafficMirrorMeta) {
	var wg sync.WaitGroup
	
	for _, dest := range spec.Destinations {
		// Check destination-specific sample rate
		if dest.SampleRate > 0 && rand.Float64() > dest.SampleRate {
			continue
		}

		wg.Add(1)
		go func(destination apidef.TrafficMirrorDestination) {
			defer wg.Done()
			t.sendSingleMirror(r, destination, spec)
		}(dest)
	}
	
	wg.Wait()
}

// sendSingleMirror sends request to a single mirror destination
func (t *TrafficMirrorMiddleware) sendSingleMirror(r *http.Request, dest apidef.TrafficMirrorDestination, spec *apidef.TrafficMirrorMeta) {
	// Clone the request for this destination
	mirrorReq, err := t.cloneRequest(r)
	if err != nil {
		t.Logger().WithError(err).Error("Failed to clone request for mirror destination")
		return
	}

	// Parse destination URL
	destURL, err := url.Parse(dest.URL)
	if err != nil {
		t.Logger().WithError(err).WithField("url", dest.URL).Error("Invalid mirror destination URL")
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

	// Add global headers
	for k, v := range spec.Headers {
		mirrorReq.Header.Set(k, v)
	}

	// Add destination-specific headers
	for k, v := range dest.Headers {
		mirrorReq.Header.Set(k, v)
	}

	// Add mirroring metadata headers
	mirrorReq.Header.Set("X-Tyk-Mirror", "true")
	mirrorReq.Header.Set("X-Tyk-Mirror-Source", r.Host)
	
	// Add timestamp for tracking
	mirrorReq.Header.Set("X-Tyk-Mirror-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	// Create client with destination-specific timeout
	client := t.client
	if dest.Timeout > 0 {
		client = &http.Client{
			Timeout: time.Duration(dest.Timeout) * time.Second,
			Transport: t.client.Transport,
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	
	mirrorReq = mirrorReq.WithContext(ctx)

	// Send the mirrored request
	resp, err := client.Do(mirrorReq)
	if err != nil {
		t.Logger().WithError(err).
			WithField("destination", dest.URL).
			Debug("Failed to send mirrored request")
		return
	}
	defer resp.Body.Close()

	// Log successful mirror (debug level to avoid spam)
	t.Logger().WithField("destination", dest.URL).
		WithField("status", resp.StatusCode).
		Debug("Successfully sent mirrored request")

	// Drain response body to allow connection reuse
	io.Copy(io.Discard, resp.Body)
}

// Unload cleans up resources
func (t *TrafficMirrorMiddleware) Unload() {
	if t.client != nil && t.client.Transport != nil {
		if transport, ok := t.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}