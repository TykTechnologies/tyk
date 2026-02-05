package gateway

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
)

// As for the HTTP methods spec:
//
//	HTTP request bodies are theoretically allowed for all methods except TRACE,
//	however they are not commonly used except in PUT, POST and PATCH. Because of this,
//	they may not be supported properly by some client frameworks, and you should not allow
//	request bodies for GET, DELETE, TRACE, OPTIONS and HEAD methods.
var skippedMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodDelete:  {},
	http.MethodTrace:   {},
	http.MethodOptions: {},
	http.MethodHead:    {},
}

// RequestSizeLimitMiddleware is a middleware that will enforce a limit on the request body size. The request has
// already been copied to memory when this middleware is called. Therefore, this middleware can't protect the gateway
// itself from large requests.
type RequestSizeLimitMiddleware struct {
	*BaseMiddleware
}

func (t *RequestSizeLimitMiddleware) Name() string {
	return "RequestSizeLimitMiddleware"
}

func (t *RequestSizeLimitMiddleware) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.SizeLimit) > 0 ||
			(!version.GlobalSizeLimitDisabled && version.GlobalSizeLimit > 0) {
			return true
		}
	}
	return false
}

func (t *RequestSizeLimitMiddleware) checkRequestLimit(r *http.Request, sizeLimit int64) (error, int) {
	statedCL := r.Header.Get(header.ContentLength)
	if statedCL == "" {
		ctx.SetErrorClassification(r, tykerrors.ClassifyRequestSizeError(tykerrors.ErrTypeContentLengthMissing, t.Name()))
		return errors.New("Content length is required for this request"), 411
	}

	size, err := strconv.ParseInt(statedCL, 0, 64)
	if err != nil {
		t.Logger().WithError(err).Error("String conversion for content length failed")
		return errors.New("content length is not a valid Integer"), http.StatusBadRequest
	}
	if r.ContentLength > size {
		size = r.ContentLength
	}

	// Check stated size
	if size > sizeLimit {
		t.Logger().WithFields(logrus.Fields{"size": size, "limit": sizeLimit}).Info("Attempted access with large request size, blocked.")
		ctx.SetErrorClassification(r, tykerrors.ClassifyRequestSizeError(tykerrors.ErrTypeBodyTooLarge, t.Name()))
		return errors.New("Request is too large"), http.StatusBadRequest
	}

	return nil, http.StatusOK
}

// RequestSizeLimit will check a request for maximum request size, this can be a global limit or a matched limit.
func (t *RequestSizeLimitMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if _, ok := skippedMethods[r.Method]; ok {
		return nil, http.StatusOK
	}

	logger := t.Logger()
	logger.Debug("Request size limiter active")

	vInfo, _ := t.Spec.Version(r)

	logger.Debug("Global limit is: ", vInfo.GlobalSizeLimit)
	// Manage global headers first
	if vInfo.GlobalSizeLimit > 0 {
		logger.Debug("Checking global limit")
		err, code := t.checkRequestLimit(r, vInfo.GlobalSizeLimit)
		// If not OK, block
		if code != http.StatusOK {
			return err, code
		}
	}

	// if there's no paths at all path check
	if len(vInfo.ExtendedPaths.SizeLimit) == 0 {
		return nil, http.StatusOK
	}

	versionPaths := t.Spec.RxPaths[vInfo.Name]

	// If there's a potential match, try to match
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, RequestSizeLimit)
	if found {
		logger.Debug("Request size limit matched for this URL, checking...")
		rmeta := meta.(*apidef.RequestSizeMeta)
		return t.checkRequestLimit(r, rmeta.SizeLimit)
	}

	return nil, http.StatusOK
}
