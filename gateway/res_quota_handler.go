package gateway

import (
	"github.com/TykTechnologies/tyk/storage"
	"net/http"
	"strconv"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/user"
)

type ResponseQuotaHandlerOptions struct {
	HeaderName          string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	PropagateHeaderName bool   `mapstructure:"propagate_header_name" bson:"propagate_header_name" json:"propagate_header_name"`
}

type ResponseQuotaHandler struct {
	BaseTykResponseHandler
	config ResponseQuotaHandlerOptions
}

func (h *ResponseQuotaHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *ResponseQuotaHandler) Name() string {
	return "ResponseQuotaHandler"
}

func (h *ResponseQuotaHandler) Enabled() bool {
	return true
}

func (h *ResponseQuotaHandler) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec

	if err := mapstructure.Decode(c, &h.config); err != nil {
		return err
	}

	if h.config.HeaderName == "" {
		h.config.HeaderName = "x-tyk-cost"
	}

	return nil
}

func (h *ResponseQuotaHandler) HandleError(rw http.ResponseWriter, r *http.Request) {
}

func (h *ResponseQuotaHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, r *http.Request, s *user.SessionState) error {

	// nothing in the header, so we don't need to do anything

	h.config.HeaderName = "x-tyk-cost"
	incrementBy := res.Header.Get(h.config.HeaderName)
	if incrementBy == "" {
		return nil
	}

	s = ctxGetSession(r)
	if s == nil {
		return nil
	}
	key := ctxGetAuthToken(r)
	if h.Gw.GetConfig().HashKeys {
		key = storage.HashStr(key)
	}

	rawKey := QuotaKeyPrefix + key

	// convert incrementBy to int64
	incrementByInt64, err := strconv.ParseInt(incrementBy, 10, 64)
	if err != nil {
		return err
	}

	storeRef := h.Gw.GlobalSessionManager.Store()
	storeRef.IncrementByWithExpire(rawKey, incrementByInt64, s.QuotaRenewalRate)

	// Manage global response header options with response_processors
	if !h.config.PropagateHeaderName {
		res.Header.Del(h.config.HeaderName)
	}

	return nil
}
