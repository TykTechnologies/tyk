package gateway

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/regexp"
)

// GranularAccessMiddleware will check if a URL is specifically enabled for the key
type GranularAccessMiddleware struct {
	*BaseMiddleware
}

func (m *GranularAccessMiddleware) Name() string {
	return "GranularAccessMiddleware"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *GranularAccessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	session := ctxGetSession(r)

	sessionVersionData, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		return nil, http.StatusOK
	}

	if len(sessionVersionData.AllowedURLs) == 0 {
		return nil, http.StatusOK
	}

	gwConfig := m.Gw.GetConfig()

	// Hook per-api settings here (m.Spec...)
	isPrefixMatch := gwConfig.HttpServerOptions.EnablePathPrefixMatching
	isSuffixMatch := gwConfig.HttpServerOptions.EnablePathSuffixMatching

	if isPrefixMatch {
		urlPaths := []string{
			m.Spec.StripListenPath(r.URL.Path),
			r.URL.Path,
		}

		logger := m.Logger().WithField("paths", urlPaths)

		for _, accessSpec := range sessionVersionData.AllowedURLs {
			if !slices.Contains(accessSpec.Methods, r.Method) {
				continue
			}

			// Append $ if so configured to match end of request path.
			pattern := httputil.PreparePathRegexp(accessSpec.URL, isPrefixMatch, isSuffixMatch)
			if isSuffixMatch && !strings.HasSuffix(pattern, "$") {
				pattern += "$"
			}

			match, err := httputil.MatchPaths(pattern, urlPaths)

			// unconditional log of err/match/url
			// if loglevel is set to debug verbosity increases and all requests are logged,
			// regardless if an error occured or not.
			if gwConfig.LogLevel == "debug" || err != nil {
				logger = logger.WithFields(logrus.Fields{
				"error":   err,
				"pattern": pattern,
				"match":   match,
			})
				if err != nil {
					logger.Error("error matching endpoint")
				} else {
					logger.Debug("matching endpoint")
				}
			}

			if err != nil || !match {
				continue
			}
			return m.pass()
		}

		return m.block(logger)
	}

	logger := m.Logger().WithField("paths", []string{r.URL.Path})

	// Legacy behaviour (5.5.0 and earlier), wildcard match against full request path.
	// Fixed error handling in regex compilation to continue to next pattern (block).
	urlPath := r.URL.Path

	for _, accessSpec := range sessionVersionData.AllowedURLs {
		if !slices.Contains(accessSpec.Methods, r.Method) {
			continue
		}

		pattern := httputil.PreparePathRegexp(accessSpec.URL, false, isSuffixMatch)

		logger.Debug("Checking: ", urlPath, " Against:", pattern)

		// Wildcard match (user supplied, as-is)
		asRegex, err := regexp.Compile(pattern)
		if err != nil {
			logger.WithError(err).Error("error compiling regex")
			continue
		}

		match := asRegex.MatchString(r.URL.Path)
		if match {
			return m.pass()
		}
	}

	return m.block(logger)
}

func (m *GranularAccessMiddleware) block(logger *logrus.Entry) (error, int) {
	logger.Info("Attempted access to unauthorised endpoint (Granular).")
	return errors.New("Access to this resource has been disallowed"), http.StatusForbidden
}

func (m *GranularAccessMiddleware) pass() (error, int) {
	return nil, http.StatusOK
}
