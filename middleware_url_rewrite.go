package main

import (
	"github.com/lonelycode/tykcommon"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"net/url"
)

type URLRewriter struct{}

func (u URLRewriter) Rewrite(thisMeta *tykcommon.URLRewriteMeta, path string) (string, error) {
	// Find all the matching groups:
	mp, mpErr := regexp.Compile(thisMeta.MatchPattern)
	if mpErr != nil {
		log.Debug("Compilation error: ", mpErr)
		return "", mpErr
	}
	log.Debug("Inbound path: ", path)
	result_slice := mp.FindAllStringSubmatch(path, -1)

	// Make sure it matches the string
	log.Debug("Rewriter checking matches, len is: ", len(result_slice))
	if len(result_slice) > 0 {
		newpath := thisMeta.RewriteTo
		// get the indices for the replacements:
		dollarMatch, _ := regexp.Compile(`\$\d+`) // Prepare our regex
		replace_slice := dollarMatch.FindAllStringSubmatch(thisMeta.RewriteTo, -1)

		log.Debug(result_slice)
		log.Debug(replace_slice)

		mapped_replace := make(map[string]string)
		for mI, replacementVal := range result_slice[0] {
			indexVal := "$" + strconv.Itoa(mI)
			mapped_replace[indexVal] = replacementVal
		}

		for _, v := range replace_slice {
			log.Debug("Replacing: ", v[0])
			newpath = strings.Replace(newpath, string(v[0]), string(mapped_replace[v[0]]), -1)
		}

		log.Debug("URL Re-written from: ", path)
		log.Debug("URL Re-written to: ", newpath)

		// matched?? Set the modified path
		return newpath, nil
	}
	return path, nil
}

// URLRewriteMiddleware Will rewrite an inbund URL to a matching outbound one, it can also handle dynamic variable substitution
type URLRewriteMiddleware struct {
	*TykMiddleware
	Rewriter *URLRewriter
}

type URLRewriteMiddlewareConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *URLRewriteMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *URLRewriteMiddleware) GetConfig() (interface{}, error) {
	log.Debug("URL Rewrite enabled")
	m.Rewriter = &URLRewriter{}
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *URLRewriteMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Uee the request status validator to see if it's in our cache list
	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := m.TykMiddleware.Spec.GetVersionData(r)
	found, meta = m.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, URLRewrite)
	if found {
		stat = StatusURLRewrite
	}

	log.Debug("Rewriter started, stat was: ", stat)

	if stat == StatusURLRewrite {
		log.Debug("Rewriter active")
		thisMeta := meta.(*tykcommon.URLRewriteMeta)
		log.Info(r.URL)
		p, pErr := m.Rewriter.Rewrite(thisMeta, r.URL.String())
		if pErr != nil {
			return pErr, 500
		}
		newURL, uErr := url.Parse(p)
		if uErr != nil {
			log.Error("URL Rewrite failed, could not parse: ", p)
		} else {
			r.URL = newURL
		}
		// r.URL.Path = p
		// if strings.Index(p, "?") != -1 {
		// 	// query string, this gets odd, so lets set the opaque value
		// 	r.URL.Opaque = "/" + p
		// }

	}
	return nil, 200
}
