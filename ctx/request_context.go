package ctx

import (
	"context"
	"net/http"
	"net/url"
	"sync"
)

type RequestContext struct {
	mu sync.RWMutex
	
	urlRewritten bool
	oldURL       *url.URL
	newURL       *url.URL
}

func (rc *RequestContext) RewriteUrl(old, new *url.URL) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if old.String() != new.String() {
		rc.urlRewritten = true
		rc.oldURL = old
		rc.newURL = new
	}
}

func (rc *RequestContext) Reset() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.urlRewritten = false
	rc.oldURL = nil
	rc.newURL = nil
}

func (rc *RequestContext) IsRewritten() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.urlRewritten
}

func GetRequestContext(r *http.Request) *RequestContext {
	if v := r.Context().Value(RequestContextKey); v != nil {
		if rc, ok := v.(*RequestContext); ok {
			return rc
		}
	}
	
	rc := &RequestContext{}
	ctx := context.WithValue(r.Context(), RequestContextKey, rc)
	h := r.WithContext(ctx)
	*r = *h
	return rc
}
