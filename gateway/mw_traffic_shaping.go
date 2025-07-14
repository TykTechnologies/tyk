package gateway

import (
	"errors"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"hash/fnv"
	"net/http"
)

var ErrTrafficShapingRejected = errors.New("request rejected by traffic shaping rules")

type TrafficShapingMiddleware struct {
	*BaseMiddleware
}

func (t *TrafficShapingMiddleware) Name() string {
	return "TrafficShapingMiddleware"
}

func (t *TrafficShapingMiddleware) EnabledForSpec() bool {
	if ext := t.Spec.GetTykExtension(); ext != nil && ext.Middleware != nil {
		for _, op := range ext.Middleware.Operations {
			if op.TrafficShaping != nil && op.TrafficShaping.Enabled {
				return true
			}
		}
	}
	return false
}

func (t *TrafficShapingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	op := t.Spec.findOperation(r)
	if op == nil || op.TrafficShaping == nil || !op.TrafficShaping.Enabled {
		return nil, http.StatusOK
	}

	routingKey := t.getRoutingValue(r, op.TrafficShaping.ConsistentRouting)
	if !t.isAllowed(routingKey, op.TrafficShaping.Percentage) {
		if altEndpoint := op.TrafficShaping.AlternativeEndpoint; altEndpoint != "" {
			http.Redirect(w, r, altEndpoint, http.StatusTemporaryRedirect)
			return nil, http.StatusTemporaryRedirect
		}
		return ErrTrafficShapingRejected, http.StatusTooManyRequests
	}

	return nil, http.StatusOK
}

func (t *TrafficShapingMiddleware) getRoutingValue(r *http.Request, routing *oas.ConsistentRouting) string {
	if routing == nil {
		return r.RemoteAddr
	}

	if routing.HeaderName != "" {
		if val := r.Header.Get(routing.HeaderName); val != "" {
			return val
		}
	}

	if routing.QueryName != "" {
		if val := r.URL.Query().Get(routing.QueryName); val != "" {
			return val
		}
	}

	return r.RemoteAddr
}

func (t *TrafficShapingMiddleware) isAllowed(routingKey string, percentage int) bool {
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}

	h := fnv.New32a()
	h.Write([]byte(routingKey))
	return (h.Sum32() % 100) < uint32(percentage)
}
