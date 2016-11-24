package main

import (
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
)

type URLRewriter struct{}

func (u URLRewriter) Rewrite(thisMeta *tykcommon.URLRewriteMeta, path string, useContext bool, r *http.Request) (string, error) {
	// Find all the matching groups:
	mp, mpErr := regexp.Compile(thisMeta.MatchPattern)
	if mpErr != nil {
		log.Debug("Compilation error: ", mpErr)
		return "", mpErr
	}
	log.Debug("Inbound path: ", path)
	newpath := path

	result_slice := mp.FindAllStringSubmatch(path, -1)
	// Make sure it matches the string
	log.Debug("Rewriter checking matches, len is: ", len(result_slice))
	if len(result_slice) > 0 {
		newpath = thisMeta.RewriteTo
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
		// return newpath, nil
	}

	if useContext {
		log.Debug("Using context")
		var contextData map[string]interface{}
		cnt, contextFound := context.GetOk(r, ContextData)

		if contextFound {
			contextData = cnt.(map[string]interface{})
		}

		dollarMatch, _ := regexp.Compile(`\$tyk_context.(\w+)`)
		replace_slice := dollarMatch.FindAllStringSubmatch(thisMeta.RewriteTo, -1)
		for _, v := range replace_slice {
			contextKey := strings.Replace(v[0], "$tyk_context.", "", 1)
			log.Debug("Replacing: ", v[0])

			if contextFound {
				tempVal, ok := contextData[contextKey]
				var nVal string
				if ok {
					switch tempVal.(type) {
					case string:
						nVal = tempVal.(string)
					case []string:
						nVal = strings.Join(tempVal.([]string), ",")
						// Remove empty start
						nVal = strings.TrimPrefix(nVal, ",")
					case url.Values:
						end := len(tempVal.(url.Values))
						i := 0
						nVal = ""
						for key, val := range tempVal.(url.Values) {
							nVal += key + ":" + strings.Join(val, ",")
							if i < end-1 {
								nVal += ";"
							}
							i++
						}
					default:
						log.Error("Context variable type is not supported: ", reflect.TypeOf(tempVal))
					}
					newpath = strings.Replace(newpath, string(v[0]), url.QueryEscape(nVal), -1)
				}

			}

		}
	}

	// Meta data from the token
	sess, sessFound := context.GetOk(r, SessionData)
	if sessFound {
		thisSessionState := sess.(SessionState)

		metaDollarMatch, _ := regexp.Compile(`\$tyk_meta.(\w+)`)
		metaReplace_slice := metaDollarMatch.FindAllStringSubmatch(thisMeta.RewriteTo, -1)
		for _, v := range metaReplace_slice {
			contextKey := strings.Replace(v[0], "$tyk_meta.", "", 1)
			log.Debug("Replacing: ", v[0])

			tempVal, ok := thisSessionState.MetaData.(map[string]interface{})[contextKey]
			if ok {
				var nVal string
				if ok {
					switch tempVal.(type) {
					case string:
						nVal = tempVal.(string)
					case []string:
						nVal = strings.Join(tempVal.([]string), ",")
						// Remove empty start
						nVal = strings.TrimPrefix(nVal, ",")
					case url.Values:
						end := len(tempVal.(url.Values))
						i := 0
						nVal = ""
						for key, val := range tempVal.(url.Values) {
							nVal += key + ":" + strings.Join(val, ",")
							if i < end-1 {
								nVal += ";"
							}
							i++
						}
					default:
						log.Error("Context variable type is not supported: ", reflect.TypeOf(tempVal))
					}
					newpath = strings.Replace(newpath, string(v[0]), url.QueryEscape(nVal), -1)
				}

			}

		}
	}

	return newpath, nil
}

// URLRewriteMiddleware Will rewrite an inbund URL to a matching outbound one, it can also handle dynamic variable substitution
type URLRewriteMiddleware struct {
	*TykMiddleware
	Rewriter *URLRewriter
}

type URLRewriteMiddlewareConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *URLRewriteMiddleware) New() {}

func (m *URLRewriteMiddleware) IsEnabledForSpec() bool {
	var used bool
	for _, thisVersion := range m.TykMiddleware.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.URLRewrite) > 0 {
			used = true
			m.TykMiddleware.Spec.URLRewriteEnabled = true
			break
		}
	}

	return used
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *URLRewriteMiddleware) GetConfig() (interface{}, error) {
	log.Debug("URL Rewrite enabled")
	m.Rewriter = &URLRewriter{}
	return nil, nil
}

func (m *URLRewriteMiddleware) CheckHostRewrite(oldPath, newTarget string, r *http.Request) {
	oldAsURL, _ := url.Parse(oldPath)
	newAsURL, _ := url.Parse(newTarget)
	if oldAsURL.Host != newAsURL.Host {
		log.Debug("Detected a host rewrite in pattern!")
		context.Set(r, RetainHost, true)
	}
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
		log.Debug(r.URL)
		oldPath := r.URL.String()
		p, pErr := m.Rewriter.Rewrite(thisMeta, r.URL.String(), true, r)
		if pErr != nil {
			return pErr, 500
		}

		m.CheckHostRewrite(oldPath, p, r)

		newURL, uErr := url.Parse(p)
		if uErr != nil {
			log.Error("URL Rewrite failed, could not parse: ", p)
		} else {
			r.URL = newURL
		}

	}
	return nil, 200
}
