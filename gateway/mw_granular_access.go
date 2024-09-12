package gateway

import (
	"errors"
	"net/http"

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

	logger := m.Logger().WithField("path", r.URL.Path)
	session := ctxGetSession(r)

	sessionVersionData, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		return nil, http.StatusOK
	}

	if len(sessionVersionData.AllowedURLs) == 0 {
		return nil, http.StatusOK
	}

<<<<<<< HEAD
	urlPath := m.Spec.StripListenPath(r.URL.Path)
=======
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
				logger = logger.WithError(err).WithField("pattern", pattern).WithField("match", match)
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
>>>>>>> 89bcc579d... WIP [TT-12865] Rename config parameter, update usage, support mux params on legacy (#6506)

	for _, accessSpec := range sessionVersionData.AllowedURLs {
		url := accessSpec.URL
		clean, err := httputil.GetPathRegexp(url)
		if err != nil {
			logger.WithError(err).Errorf("error getting path regex: %q, skipping", url)
			continue
		}

<<<<<<< HEAD
		asRegex, err := regexp.Compile(clean)
=======
		pattern := httputil.PreparePathRegexp(accessSpec.URL, false, isSuffixMatch)

		logger.Debug("Checking: ", urlPath, " Against:", pattern)

		// Wildcard match (user supplied, as-is)
		asRegex, err := regexp.Compile(pattern)
>>>>>>> 89bcc579d... WIP [TT-12865] Rename config parameter, update usage, support mux params on legacy (#6506)
		if err != nil {
			logger.WithError(err).Errorf("error compiling path regex: %q, skipping", url)
			continue
		}

		match := asRegex.MatchString(urlPath)

		logger.WithField("pattern", url).WithField("match", match).Debug("checking allowed url")

		if match {
			// if a path is matched, but isn't matched on method,
			// then we continue onto the next path for evaluation.
			for _, method := range accessSpec.Methods {
				if method == r.Method {
					return nil, http.StatusOK
				}
			}
		}
	}

	logger.Info("Attempted access to unauthorised endpoint (Granular).")

	return errors.New("Access to this resource has been disallowed"), http.StatusForbidden

}
