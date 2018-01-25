package main

import (
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"fmt"
	"io/ioutil"
	"net/textproto"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
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

	// Check triggers
	rewriteToPath := meta.RewriteTo
	if len(meta.Triggers) > 0 {

		// This feature uses context, we must force it if it doesn't exist
		contextData := ctxGetData(r)
		if contextData == nil {
			contextDataObject := make(map[string]interface{})
			ctxSetData(r, contextDataObject)
		}

		for tn, triggerOpts := range meta.Triggers {
			checkAny := false
			setCount := 0
			if triggerOpts.On == apidef.Any {
				checkAny = true
			}

			// Check headers
			if len(triggerOpts.Options.HeaderMatches) > 0 {
				if checkHeaderTrigger(r, triggerOpts.Options.HeaderMatches, checkAny, tn) {
					setCount += 1
					if checkAny {
						rewriteToPath = triggerOpts.RewriteTo
						break
					}
				}
			}

			// Check query string
			if len(triggerOpts.Options.QueryValMatches) > 0 {
				if checkQueryString(r, triggerOpts.Options.QueryValMatches, checkAny, tn) {
					setCount += 1
					if checkAny {
						rewriteToPath = triggerOpts.RewriteTo
						break
					}
				}
			}

			// Check path parts
			if len(triggerOpts.Options.PathPartMatches) > 0 {
				if checkPathParts(r, triggerOpts.Options.PathPartMatches, checkAny, tn) {
					setCount += 1
					if checkAny {
						rewriteToPath = triggerOpts.RewriteTo
						break
					}
				}
			}

			// Check session meta

			if session := ctxGetSession(r); session != nil {
				if len(triggerOpts.Options.SessionMetaMatches) > 0 {
					if checkSessionTrigger(r, session, triggerOpts.Options.SessionMetaMatches, checkAny, tn) {
						setCount += 1
						if checkAny {
							rewriteToPath = triggerOpts.RewriteTo
							break
						}
					}
				}
			}

			// Check payload
			if triggerOpts.Options.PayloadMatches.MatchPattern != "" {
				if checkPayload(r, triggerOpts.Options.PayloadMatches, tn) {
					setCount += 1
					if checkAny {
						rewriteToPath = triggerOpts.RewriteTo
						break
					}
				}
			}

			if !checkAny {
				// Set total count:
				total := 0
				if len(triggerOpts.Options.HeaderMatches) > 0 {
					total += 1
				}
				if len(triggerOpts.Options.QueryValMatches) > 0 {
					total += 1
				}
				if len(triggerOpts.Options.PathPartMatches) > 0 {
					total += 1
				}
				if len(triggerOpts.Options.SessionMetaMatches) > 0 {
					total += 1
				}
				if triggerOpts.Options.PayloadMatches.MatchPattern != "" {
					total += 1
				}
				if total == setCount {
					rewriteToPath = triggerOpts.RewriteTo
				}
			}
		}
	}

	// Make sure it matches the string
	log.Debug("Rewriter checking matches, len is: ", len(result_slice))
	if len(result_slice) > 0 {
		newpath = rewriteToPath
		// get the indices for the replacements:
		dollarMatch := regexp.MustCompile(`\$\d+`) // Prepare our regex
		replace_slice := dollarMatch.FindAllStringSubmatch(rewriteToPath, -1)

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

	dollarMatch := regexp.MustCompile(`\$tyk_context.([A-Za-z0-9_\-\.]+)`)
	replace_slice := dollarMatch.FindAllStringSubmatch(rewriteToPath, -1)
	for _, v := range replace_slice {
		contextKey := strings.Replace(v[0], "$tyk_context.", "", 1)

		if val, ok := contextData[contextKey]; ok {
			newpath = strings.Replace(newpath, v[0],
				url.QueryEscape(valToStr(val)), -1)
		}
	}

	// Meta data from the token
	if session := ctxGetSession(r); session != nil {

		metaDollarMatch := regexp.MustCompile(`\$tyk_meta.(\w+)`)
		metaReplace_slice := metaDollarMatch.FindAllStringSubmatch(rewriteToPath, -1)
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

func (m *URLRewriteMiddleware) InitTriggerRx() {
	// Generate regexp for each special match parameter
	for verKey := range m.Spec.VersionData.Versions {
		for pathKey := range m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite {
			for trKey := range m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].Triggers {
				for key, h := range m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
					Triggers[trKey].Options.HeaderMatches {
					h.Init()
					m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
						Triggers[trKey].Options.HeaderMatches[key] = h
				}
				for key, q := range m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
					Triggers[trKey].Options.QueryValMatches {
					q.Init()
					m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
						Triggers[trKey].Options.QueryValMatches[key] = q
				}
				for key, h := range m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
					Triggers[trKey].Options.SessionMetaMatches {
					h.Init()
					m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
						Triggers[trKey].Options.SessionMetaMatches[key] = h
				}
				for key, h := range m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
					Triggers[trKey].Options.PathPartMatches {
					h.Init()
					m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
						Triggers[trKey].Options.PathPartMatches[key] = h
				}
				if m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
					Triggers[trKey].Options.PayloadMatches.MatchPattern != "" {
					m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey].
						Triggers[trKey].Options.PayloadMatches.Init()
				}
			}
		}
	}
}

func (m *URLRewriteMiddleware) EnabledForSpec() bool {
	for _, version := range m.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.URLRewrite) > 0 {
			m.Spec.URLRewriteEnabled = true
			m.InitTriggerRx()
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

func checkHeaderTrigger(r *http.Request, options map[string]apidef.StringRegexMap, any bool, triggernum int) bool {
	contextData := ctxGetData(r)
	fCount := 0
	for mh, mr := range options {
		mhCN := textproto.CanonicalMIMEHeaderKey(mh)
		vals, ok := r.Header[mhCN]
		if ok {
			for i, v := range vals {
				b := mr.Check(v)
				if len(b) > 0 {
					kn := fmt.Sprintf("trigger-%d-%s-%d", triggernum, mhCN, i)
					contextData[kn] = b
					fCount++
				}
			}
		}
	}

	if fCount > 0 {
		ctxSetData(r, contextData)
		if any {
			return true
		}

		return len(options) <= fCount
	}

	return false
}

func checkQueryString(r *http.Request, options map[string]apidef.StringRegexMap, any bool, triggernum int) bool {
	contextData := ctxGetData(r)
	fCount := 0
	for mv, mr := range options {
		qvals := r.URL.Query()
		vals, ok := qvals[mv]
		if ok {
			for i, v := range vals {
				b := mr.Check(v)
				if len(b) > 0 {
					kn := fmt.Sprintf("trigger-%d-%s-%d", triggernum, mv, i)
					contextData[kn] = b
					fCount++
				}
			}
		}
	}

	if fCount > 0 {
		ctxSetData(r, contextData)
		if any {
			return true
		}

		return len(options) <= fCount
	}

	return false
}

func checkPathParts(r *http.Request, options map[string]apidef.StringRegexMap, any bool, triggernum int) bool {
	contextData := ctxGetData(r)
	fCount := 0
	for mv, mr := range options {
		pathParts := strings.Split(r.URL.Path, "/")

		for _, part := range pathParts {
			b := mr.Check(part)
			if len(b) > 0 {
				kn := fmt.Sprintf("trigger-%d-%s-%d", triggernum, mv, fCount)
				contextData[kn] = b
				fCount++
			}
		}
	}

	if fCount > 0 {
		ctxSetData(r, contextData)
		if any {
			return true
		}

		return len(options) <= fCount
	}

	return false
}

func checkSessionTrigger(r *http.Request, sess *user.SessionState, options map[string]apidef.StringRegexMap, any bool, triggernum int) bool {
	contextData := ctxGetData(r)
	fCount := 0
	for mh, mr := range options {
		rawVal, ok := sess.MetaData[mh]
		if ok {
			val, valOk := rawVal.(string)
			if valOk {
				b := mr.Check(val)
				if len(b) > 0 {
					kn := fmt.Sprintf("trigger-%d-%s", triggernum, mh)
					contextData[kn] = b
					fCount++
				}
			}
		}
	}

	if fCount > 0 {
		ctxSetData(r, contextData)
		if any {
			return true
		}

		return len(options) <= fCount
	}

	return false
}

func checkPayload(r *http.Request, options apidef.StringRegexMap, triggernum int) bool {
	contextData := ctxGetData(r)
	cp := copyRequest(r)
	bodyBytes, _ := ioutil.ReadAll(cp.Body)

	b := options.Check(string(bodyBytes))
	if len(b) > 0 {
		kn := fmt.Sprintf("trigger-%d-payload", triggernum)
		contextData[kn] = string(b)
		return true
	}

	return false
}
