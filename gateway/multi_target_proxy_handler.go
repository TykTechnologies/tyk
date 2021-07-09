package gateway

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
)

type MultiTargetProxy struct {
	versionProxies map[string]*ReverseProxy
	specReference  *APISpec
	defaultProxy   *ReverseProxy
}

func (m *MultiTargetProxy) proxyForRequest(r *http.Request) *ReverseProxy {
	version, _, _, _ := m.specReference.Version(r)
	if proxy := m.versionProxies[version.Name]; proxy != nil {
		return proxy
	}
	log.WithFields(logrus.Fields{
		"prefix": "multi-target",
	}).Warning("No proxy found, using default")
	return m.defaultProxy
}

func (m *MultiTargetProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) ProxyResponse {
	log.WithFields(logrus.Fields{
		"prefix": "multi-target",
	}).Debug("Serving Multi-target...")
	return m.proxyForRequest(r).ServeHTTP(w, r)
}

func (m *MultiTargetProxy) ServeHTTPForCache(w http.ResponseWriter, r *http.Request) ProxyResponse {
	return m.proxyForRequest(r).ServeHTTPForCache(w, r)
}

func (m *MultiTargetProxy) CopyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) {
	m.defaultProxy.CopyResponse(dst, src, flushInterval)
}

func (gw *Gateway) NewMultiTargetProxy(spec *APISpec, logger *logrus.Entry) *MultiTargetProxy {
	m := &MultiTargetProxy{}
	m.versionProxies = make(map[string]*ReverseProxy)
	m.specReference = spec
	m.defaultProxy = gw.TykNewSingleHostReverseProxy(spec.target, spec, logger)

	for vname, vdata := range spec.VersionData.Versions {
		if vdata.OverrideTarget == "" {
			log.WithFields(logrus.Fields{
				"prefix": "multi-target",
			}).Info("----> Version ", vname, " has no override target")
			m.versionProxies[vname] = m.defaultProxy
			continue
		}
		remote, err := url.Parse(vdata.OverrideTarget)
		log.WithFields(logrus.Fields{
			"prefix": "multi-target",
		}).Info("----> Version ", vname, " has '", vdata.OverrideTarget, "' for override target")
		log.WithFields(logrus.Fields{
			"prefix": "multi-target",
		}).Debug("Multi-target URL: ", vdata.OverrideTarget)
		log.WithFields(logrus.Fields{
			"prefix": "multi-target",
		}).Debug("Multi-target URL (obj): ", remote)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "multi-target",
			}).Error("Couldn't parse version target URL in MultiTarget: ", err)
		}
		m.versionProxies[vname] = gw.TykNewSingleHostReverseProxy(remote, spec, logger)
	}
	return m
}
