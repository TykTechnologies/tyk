//go:build !v52
// +build !v52

package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

func (rt *TykRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {

	hasInternalHeader := r.Header.Get(apidef.TykInternalApiHeader) != ""

	if r.URL.Scheme == "tyk" || hasInternalHeader {
		if hasInternalHeader {
			r.Header.Del(apidef.TykInternalApiHeader)
		}

		handler, _, found := rt.Gw.findInternalHttpHandlerByNameOrID(r.Host)
		if !found {
			rt.logger.WithField("looping_url", "tyk://"+r.Host).Error("Couldn't detect target")
			return nil, errors.New("handler could")
		}

		rt.logger.WithField("looping_url", "tyk://"+r.Host).Debug("Executing request on internal route")

		return handleInMemoryLoop(handler, r)
	}

	if rt.h2ctransport != nil {
		return rt.h2ctransport.RoundTrip(r)
	}

	return rt.transport.RoundTrip(r)
}
