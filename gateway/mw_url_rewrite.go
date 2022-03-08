package gateway

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

const (
	metaLabel        = "$tyk_meta."
	contextLabel     = "$tyk_context."
	consulLabel      = "$secret_consul."
	vaultLabel       = "$secret_vault."
	envLabel         = "$secret_env."
	secretsConfLabel = "$secret_conf."
	triggerKeyPrefix = "trigger"
	triggerKeySep    = "-"
)

var dollarMatch = regexp.MustCompile(`\$\d+`)
var contextMatch = regexp.MustCompile(`\$tyk_context.([A-Za-z0-9_\-\.]+)`)
var consulMatch = regexp.MustCompile(`\$secret_consul.([A-Za-z0-9\/\-\.]+)`)
var vaultMatch = regexp.MustCompile(`\$secret_vault.([A-Za-z0-9\/\-\.]+)`)
var envValueMatch = regexp.MustCompile(`\$secret_env.([A-Za-z0-9_\-\.]+)`)
var metaMatch = regexp.MustCompile(`\$tyk_meta.([A-Za-z0-9_\-\.]+)`)
var secretsConfMatch = regexp.MustCompile(`\$secret_conf.([A-Za-z0-9[.\-\_]+)`)

func (gw *Gateway) urlRewrite(meta *apidef.URLRewriteMeta, r *http.Request) (string, error) {
	path := r.URL.String()
	log.Debug("Inbound path: ", path)
	newpath := path

	if meta.MatchRegexp == nil {
		var err error
		meta.MatchRegexp, err = regexp.Compile(meta.MatchPattern)
		if err != nil {
			return path, fmt.Errorf("URLRewrite regexp error %s", meta.MatchPattern)
		}
	}

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

			// Request context meta
			if len(triggerOpts.Options.RequestContextMatches) > 0 {
				if checkContextTrigger(r, triggerOpts.Options.RequestContextMatches, checkAny, tn) {
					setCount += 1
					if checkAny {
						rewriteToPath = triggerOpts.RewriteTo
						break
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
				if len(triggerOpts.Options.RequestContextMatches) > 0 {
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

	matchGroups := meta.MatchRegexp.FindAllStringSubmatch(path, -1)

	// Make sure it matches the string
	log.Debug("Rewriter checking matches, len is: ", len(matchGroups))
	if len(matchGroups) > 0 {
		newpath = rewriteToPath
		// get the indices for the replacements:
		replaceGroups := dollarMatch.FindAllStringSubmatch(rewriteToPath, -1)

		log.Debug(matchGroups)
		log.Debug(replaceGroups)

		groupReplace := make(map[string]string)
		for mI, replacementVal := range matchGroups[0] {
			indexVal := "$" + strconv.Itoa(mI)
			groupReplace[indexVal] = replacementVal
		}

		for _, v := range replaceGroups {
			newpath = strings.Replace(newpath, v[0], groupReplace[v[0]], -1)
		}

		log.Debug("URL Re-written from: ", path)
		log.Debug("URL Re-written to: ", newpath)

		// put url_rewrite path to context to be used in ResponseTransformMiddleware
		ctxSetUrlRewritePath(r, path)
	}

	newpath = gw.replaceTykVariables(r, newpath, true)

	return newpath, nil
}

func (gw *Gateway) replaceTykVariables(r *http.Request, in string, escape bool) string {

	if strings.Contains(in, secretsConfLabel) {
		contextData := ctxGetData(r)
		vars := secretsConfMatch.FindAllString(in, -1)
		in = gw.replaceVariables(in, vars, contextData, secretsConfLabel, escape)
	}

	if strings.Contains(in, envLabel) {
		contextData := ctxGetData(r)
		vars := envValueMatch.FindAllString(in, -1)
		in = gw.replaceVariables(in, vars, contextData, envLabel, escape)
	}

	if strings.Contains(in, vaultLabel) {
		contextData := ctxGetData(r)
		vars := vaultMatch.FindAllString(in, -1)
		in = gw.replaceVariables(in, vars, contextData, vaultLabel, escape)
	}

	if strings.Contains(in, consulLabel) {
		contextData := ctxGetData(r)
		vars := consulMatch.FindAllString(in, -1)
		in = gw.replaceVariables(in, vars, contextData, consulLabel, escape)
	}

	if strings.Contains(in, contextLabel) {
		contextData := ctxGetData(r)
		vars := contextMatch.FindAllString(in, -1)
		in = gw.replaceVariables(in, vars, contextData, contextLabel, escape)
	}

	if strings.Contains(in, metaLabel) {
		vars := metaMatch.FindAllString(in, -1)
		session := ctxGetSession(r)
		if session == nil {
			in = gw.replaceVariables(in, vars, nil, metaLabel, escape)
		} else {
			in = gw.replaceVariables(in, vars, session.MetaData, metaLabel, escape)
		}
	}
	//todo add config_data
	return in
}

func (gw *Gateway) replaceVariables(in string, vars []string, vals map[string]interface{}, label string, escape bool) string {

	emptyStringFn := func(key, in, val string) string {
		in = strings.Replace(in, val, "", -1)
		log.WithFields(logrus.Fields{
			"key":       key,
			"value":     val,
			"in string": in,
		}).Debug("Replaced with an empty string")

		return in
	}

	for _, v := range vars {
		key := strings.Replace(v, label, "", 1)

		switch label {

		case secretsConfLabel:

			secrets := gw.GetConfig().Secrets

			val, ok := secrets[key]
			if !ok || val == "" {
				in = emptyStringFn(key, in, v)
				continue
			}

			in = strings.Replace(in, v, val, -1)

		case envLabel:

			val := os.Getenv(fmt.Sprintf("TYK_SECRET_%s", strings.ToUpper(key)))
			if val == "" {
				in = emptyStringFn(key, in, v)
				continue
			}

			in = strings.Replace(in, v, val, -1)

		case vaultLabel:

			if err := gw.setUpVault(); err != nil {
				in = emptyStringFn(key, in, v)
				continue
			}

			val, err := gw.vaultKVStore.Get(key)
			if err != nil {
				in = emptyStringFn(key, in, v)
				continue
			}

			in = strings.Replace(in, v, val, -1)

		case consulLabel:

			if err := gw.setUpConsul(); err != nil {
				in = emptyStringFn(key, in, v)
				continue
			}

			val, err := gw.consulKVStore.Get(key)
			if err != nil {
				in = strings.Replace(in, v, "", -1)
				continue
			}

			in = strings.Replace(in, v, val, -1)

		default:

			val, ok := vals[key]
			if ok {
				valStr := valToStr(val)
				// If contains url with domain
				if escape && !strings.HasPrefix(valStr, "http") {
					valStr = url.QueryEscape(valStr)
				}
				in = strings.Replace(in, v, valStr, -1)
				continue
			}

			in = emptyStringFn(key, in, v)
		}
	}

	return in
}

func valToStr(v interface{}) string {
	s := ""
	switch x := v.(type) {
	case string:
		s = x
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 32)
	case int64:
		s = strconv.FormatInt(x, 10)
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
	case []interface{}:
		tmpSlice := make([]string, 0, len(x))
		for _, val := range x {
			if rec := valToStr(val); rec != "" {
				tmpSlice = append(tmpSlice, url.QueryEscape(rec))
			}
		}
		s = strings.Join(tmpSlice, ",")
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
			rewrite := m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey]

			for trKey := range rewrite.Triggers {
				tr := rewrite.Triggers[trKey]

				for key, h := range tr.Options.HeaderMatches {
					h.Init()
					tr.Options.HeaderMatches[key] = h
				}
				for key, q := range tr.Options.QueryValMatches {
					q.Init()
					tr.Options.QueryValMatches[key] = q
				}
				for key, h := range tr.Options.SessionMetaMatches {
					h.Init()
					tr.Options.SessionMetaMatches[key] = h
				}
				for key, h := range tr.Options.RequestContextMatches {
					h.Init()
					tr.Options.RequestContextMatches[key] = h
				}
				for key, h := range tr.Options.PathPartMatches {
					h.Init()
					tr.Options.PathPartMatches[key] = h
				}
				if tr.Options.PayloadMatches.MatchPattern != "" {
					tr.Options.PayloadMatches.Init()
				}

				rewrite.Triggers[trKey] = tr
			}

			m.Spec.VersionData.Versions[verKey].ExtendedPaths.URLRewrite[pathKey] = rewrite
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
	oldAsURL, errParseOld := url.Parse(oldPath)
	if errParseOld != nil {
		log.WithError(errParseOld).WithField("url", oldPath).Error("could not parse")
		return
	}

	newAsURL, errParseNew := url.Parse(newTarget)
	if errParseNew != nil {
		log.WithError(errParseNew).WithField("url", newTarget).Error("could not parse")
		return
	}

	if newAsURL.Scheme != LoopScheme && oldAsURL.Host != newAsURL.Host {
		log.Debug("Detected a host rewrite in pattern!")
		setCtxValue(r, ctx.RetainHost, true)
	}
}

const LoopScheme = "tyk"

var NonAlphaNumRE = regexp.MustCompile("[^A-Za-z0-9]+")
var LoopHostRE = regexp.MustCompile("tyk://([^/]+)")

func replaceNonAlphaNumeric(in string) string {
	return NonAlphaNumRE.ReplaceAllString(in, "-")
}

func LoopingUrl(host string) string {
	return LoopScheme + "://" + replaceNonAlphaNumeric(host)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *URLRewriteMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, _ := m.Spec.Version(r)
	found, meta := m.Spec.CheckSpecMatchesStatus(r, m.Spec.RxPaths[vInfo.Name], URLRewrite)

	if !found {
		return nil, http.StatusOK
	}

	//Used for looping feature
	//To get host and query parameters
	ctxSetOrigRequestURL(r, r.URL)

	log.Debug("Rewriter active")
	umeta := meta.(*apidef.URLRewriteMeta)
	log.Debug(r.URL)
	oldPath := r.URL.String()
	p, err := m.Gw.urlRewrite(umeta, r)
	if err != nil {
		log.Error(err)
		return err, http.StatusInternalServerError
	}

	// During looping target can be API name
	// Need make it compatible with URL parser
	if strings.HasPrefix(p, LoopScheme) {
		p = LoopHostRE.ReplaceAllStringFunc(p, func(match string) string {
			host := strings.TrimPrefix(match, LoopScheme+"://")
			return LoopingUrl(host)
		})
	}

	m.CheckHostRewrite(oldPath, p, r)

	newURL, err := url.Parse(p)
	if err != nil {
		log.Error("URL Rewrite failed, could not parse: ", p)
	} else {
		//Setting new path here breaks request middleware
		//New path is set in DummyProxyHandler/Cache middleware
		ctxSetURLRewriteTarget(r, newURL)
	}
	return nil, http.StatusOK
}

func checkHeaderTrigger(r *http.Request, options map[string]apidef.StringRegexMap, any bool, triggernum int) bool {
	contextData := ctxGetData(r)
	fCount := 0
	for mh, mr := range options {
		mhCN := textproto.CanonicalMIMEHeaderKey(mh)
		vals, ok := r.Header[mhCN]
		if ok {
			for i, v := range vals {
				matched, match := mr.FindStringSubmatch(v)
				if matched {
					addMatchToContextData(contextData, match, triggernum, mhCN, i)
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
				matched, match := mr.FindStringSubmatch(v)
				if matched {
					addMatchToContextData(contextData, match, triggernum, mv, i)
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
			matched, match := mr.FindStringSubmatch(part)
			if matched {
				addMatchToContextData(contextData, match, triggernum, mv, fCount)
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
				matched, match := mr.FindStringSubmatch(val)
				if matched {
					addMatchToContextData(contextData, match, triggernum, mh)
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

func checkContextTrigger(r *http.Request, options map[string]apidef.StringRegexMap, any bool, triggernum int) bool {
	contextData := ctxGetData(r)
	fCount := 0

	for mh, mr := range options {
		rawVal, ok := contextData[mh]

		if ok {
			val, valOk := rawVal.(string)
			if valOk {
				matched, match := mr.FindStringSubmatch(val)
				if matched {
					addMatchToContextData(contextData, match, triggernum, mh)
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
	bodyBytes, _ := ioutil.ReadAll(r.Body)

	matched, matches := options.FindAllStringSubmatch(string(bodyBytes), -1)

	if matched {
		kn := buildTriggerKey(triggernum, "payload")
		if len(matches) == 0 {
			return true
		}
		contextData[kn] = matches[0][0]

		for i, match := range matches {
			if len(match) > 0 {
				addMatchToContextData(contextData, match, triggernum, "payload", i)
			}
		}
		return true
	}

	return false
}

func addMatchToContextData(cd map[string]interface{}, match []string, trNum int, trName string, indices ...int) {
	kn := buildTriggerKey(trNum, trName, indices...)
	if len(match) == 0 {
		return
	}

	cd[kn] = match[0]

	if len(match) > 1 {
		addGroupsToContextData(cd, kn, match[1:])
	}
}

func buildTriggerKey(num int, name string, indices ...int) string {
	parts := []string{triggerKeyPrefix, strconv.Itoa(num), name}

	if len(indices) > 0 {
		for _, index := range indices {
			parts = append(parts, strconv.Itoa(index))
		}
	}

	return strings.Join(parts, triggerKeySep)
}

func addGroupsToContextData(cd map[string]interface{}, keyPrefix string, groups []string) {
	for i, g := range groups {
		k := strings.Join([]string{keyPrefix, strconv.Itoa(i)}, triggerKeySep)
		cd[k] = g
	}
}
