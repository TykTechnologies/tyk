package main

import (
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

func urlRewrite(meta *apidef.URLRewriteMeta, r *http.Request) (string, error) {
	// Find all the matching groups:
	mp, err := regexp.Compile(meta.MatchPattern)
	if err != nil {
		log.Debug("Compilation error: ", err)
		return "", err
	}
	path := r.URL.String()
	log.Debug("Inbound path: ", path)
	newpath := path

	result_slice := mp.FindAllStringSubmatch(path, -1)
	// Make sure it matches the string
	log.Debug("Rewriter checking matches, len is: ", len(result_slice))
	if len(result_slice) > 0 {
		newpath = meta.RewriteTo
		// get the indices for the replacements:
		dollarMatch := regexp.MustCompile(`\$\d+`) // Prepare our regex
		replace_slice := dollarMatch.FindAllStringSubmatch(meta.RewriteTo, -1)

		log.Debug(result_slice)
		log.Debug(replace_slice)

		mapped_replace := make(map[string]string)
		for mI, replacementVal := range result_slice[0] {
			indexVal := "$" + strconv.Itoa(mI)
			mapped_replace[indexVal] = replacementVal
		}

		for _, v := range replace_slice {
			log.Debug("Replacing: ", v[0])
			newpath = strings.Replace(newpath, v[0], mapped_replace[v[0]], -1)
		}

		log.Debug("URL Re-written from: ", path)
		log.Debug("URL Re-written to: ", newpath)

		// put url_rewrite path to context to be used in ResponseTransformMiddleware
		ctxSetUrlRewritePath(r, meta.Path)

		// matched?? Set the modified path
		// return newpath, nil
	}

	contextData := ctxGetData(r)

	dollarMatch := regexp.MustCompile(`\$tyk_context.(\w+)`)
	replace_slice := dollarMatch.FindAllStringSubmatch(meta.RewriteTo, -1)
	for _, v := range replace_slice {
		contextKey := strings.Replace(v[0], "$tyk_context.", "", 1)
		log.Debug("Replacing: ", v[0])

		if val, ok := contextData[contextKey]; ok {
			newpath = strings.Replace(newpath, v[0],
				url.QueryEscape(valToStr(val)), -1)
		}
	}

	// Meta data from the token
	if session := ctxGetSession(r); session != nil {

		metaDollarMatch := regexp.MustCompile(`\$tyk_meta.(\w+)`)
		metaReplace_slice := metaDollarMatch.FindAllStringSubmatch(meta.RewriteTo, -1)
		for _, v := range metaReplace_slice {
			contextKey := strings.Replace(v[0], "$tyk_meta.", "", 1)
			log.Debug("Replacing: ", v[0])

			val, ok := session.MetaData[contextKey]
			if ok {
				newpath = strings.Replace(newpath, v[0],
					url.QueryEscape(valToStr(val)), -1)
			}

		}
	}

	return newpath, nil
}

func valToStr(v interface{}) string {
	s := ""
	switch x := v.(type) {
	case string:
		s = x
	case []string:
		s = strings.Join(x, ",")
		// Remove empty start
		s = strings.TrimPrefix(s, ",")
	case url.Values:
		i := 0
		for key, v := range x {
			s += key + ":" + strings.Join(v, ",")
			if i < len(x)-1 {
				s += ";"
			}
			i++
		}
	default:
		log.Error("Context variable type is not supported: ", reflect.TypeOf(v))
	}
	return s
}

// URLRewriteMiddleware Will rewrite an inbund URL to a matching outbound one, it can also handle dynamic variable substitution
type URLRewriteMiddleware struct {
	BaseMiddleware
}

func (m *URLRewriteMiddleware) Name() string {
	return "URLRewriteMiddleware"
}

func (m *URLRewriteMiddleware) EnabledForSpec() bool {
	for _, version := range m.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.URLRewrite) > 0 {
			m.Spec.URLRewriteEnabled = true
			return true
		}
	}
	return false
}

func (m *URLRewriteMiddleware) CheckHostRewrite(oldPath, newTarget string, r *http.Request) {
	oldAsURL, _ := url.Parse(oldPath)
	newAsURL, _ := url.Parse(newTarget)
	if oldAsURL.Host != newAsURL.Host {
		log.Debug("Detected a host rewrite in pattern!")
		setCtxValue(r, RetainHost, true)
	}
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *URLRewriteMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := m.Spec.Version(r)
	found, meta := m.Spec.CheckSpecMatchesStatus(r, versionPaths, URLRewrite)
	if !found {
		return nil, 200
	}

	log.Debug("Rewriter active")
	umeta := meta.(*apidef.URLRewriteMeta)
	log.Debug(r.URL)
	oldPath := r.URL.String()
	p, err := urlRewrite(umeta, r)
	if err != nil {
		return err, 500
	}

	m.CheckHostRewrite(oldPath, p, r)

	newURL, err := url.Parse(p)
	if err != nil {
		log.Error("URL Rewrite failed, could not parse: ", p)
	} else {
		r.URL = newURL
	}
	return nil, 200
}
