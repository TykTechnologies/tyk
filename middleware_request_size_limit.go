package main

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tyk/apidef"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type RequestSizeLimitMiddleware struct {
	*TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (t *RequestSizeLimitMiddleware) New() {}

func (t *RequestSizeLimitMiddleware) GetName() string {
	return "RequestSizeLimitMiddleware"
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *RequestSizeLimitMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (t *RequestSizeLimitMiddleware) IsEnabledForSpec() bool {
	var used bool
	for _, version := range t.TykMiddleware.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.SizeLimit) > 0 {
			used = true
			break
		}
	}

	return used
}

func (t *RequestSizeLimitMiddleware) checkRequestLimit(r *http.Request, sizeLimit int64) (error, int) {
	statedCL := r.Header.Get("Content-Length")
	if statedCL == "" {
		return errors.New("Content length is required for this request"), 411
	}

	asInt, err := strconv.Atoi(statedCL)
	if err != nil {
		log.Error("String conversion for content length failed:", err)
		return errors.New("content length is not a valid Integer"), 400
	}

	// Check stated size
	if int64(asInt) > sizeLimit {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"size":   statedCL,
			"limit":  sizeLimit,
		}).Info("Attempted access with large request size, blocked.")

		return errors.New("Request is too large"), 400
	}

	// Check actual size
	if r.ContentLength > sizeLimit {
		// Request size is too big for globals
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"size":   r.ContentLength,
			"limit":  sizeLimit,
		}).Info("Attempted access with large request size, blocked.")

		return errors.New("Request is too large"), 400
	}

	return nil, 200
}

// RequestSizeLimit will check a request for maximum request size, this can be a global limit or a matched limit.
func (t *RequestSizeLimitMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	log.Debug("Request size limiter active")

	vInfo, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)

	log.Debug("Global limit is: ", vInfo.GlobalSizeLimit)
	// Manage global headers first
	if vInfo.GlobalSizeLimit > 0 {
		log.Debug("Checking global limit")
		err, code := t.checkRequestLimit(r, vInfo.GlobalSizeLimit)
		// If not OK, block
		if code != 200 {
			return err, code
		}
	}

	// if there's no paths at all path check
	if len(vInfo.ExtendedPaths.SizeLimit) == 0 {
		return nil, 200
	}

	// If there's a potential match, try to match
	found, meta := t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, RequestSizeLimit)
	if found {
		log.Debug("Request size limit matched for this URL, checking...")
		rmeta := meta.(*apidef.RequestSizeMeta)
		return t.checkRequestLimit(r, rmeta.SizeLimit)
	}

	return nil, 200
}
