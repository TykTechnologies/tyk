package osin

import (
	"net/http"
	"time"
)

// InfoRequest is a request for information about some AccessData
type InfoRequest struct {
	Code       string      // Code to look up
	AccessData *AccessData // AccessData associated with Code
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()
	bearer := CheckBearerAuth(r)
	if bearer == nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, nil, "handle_info_request=%s", "bearer is nil")
		return nil
	}

	// generate info request
	ret := &InfoRequest{
		Code: bearer.Code,
	}

	if ret.Code == "" {
		s.setErrorAndLog(w, E_INVALID_REQUEST, nil, "handle_info_request=%s", "code is nil")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = w.Storage.LoadAccess(ret.Code)
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, err, "handle_info_request=%s", "failed to load access data")
		return nil
	}
	if ret.AccessData == nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, nil, "handle_info_request=%s", "access data is nil")
		return nil
	}
	if ret.AccessData.Client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "handle_info_request=%s", "access data client is nil")
		return nil
	}
	if ret.AccessData.Client.GetRedirectUri() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "handle_info_request=%s", "access data client redirect uri is empty")
		return nil
	}
	if ret.AccessData.IsExpiredAt(s.Now()) {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "handle_info_request=%s", "access data is expired")
		return nil
	}

	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["client_id"] = ir.AccessData.Client.GetId()
	w.Output["access_token"] = ir.AccessData.AccessToken
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessData.CreatedAt.Add(time.Duration(ir.AccessData.ExpiresIn)*time.Second).Sub(s.Now()) / time.Second
	if ir.AccessData.RefreshToken != "" {
		w.Output["refresh_token"] = ir.AccessData.RefreshToken
	}
	if ir.AccessData.Scope != "" {
		w.Output["scope"] = ir.AccessData.Scope
	}
}
