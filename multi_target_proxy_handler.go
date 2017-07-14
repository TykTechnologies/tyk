package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/Sirupsen/logrus"
)

type MultiTargetProxy struct {
	VersionProxyMap map[string]*ReverseProxy
	specReference   *APISpec
	defaultProxy    *ReverseProxy
}

func (m *MultiTargetProxy) getProxyForRequest(r *http.Request) (*ReverseProxy, error) {
	version, _, _, _ := m.specReference.Version(r)
	proxy, found := m.VersionProxyMap[version.Name]

	if !found {
		return nil, errors.New("proxy not found")
	}

	return proxy, nil
}

func (m *MultiTargetProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) *http.Response {
	log.WithFields(logrus.Fields{
		"prefix": "multi-target",
	}).Debug("Serving Multi-target...")
	proxy, err := m.getProxyForRequest(r)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "multi-target",
		}).Warning("No proxy found, using default")
		return m.defaultProxy.ServeHTTP(rw, r)
	}

	return proxy.ServeHTTP(rw, r)
}
func (m *MultiTargetProxy) ServeHTTPForCache(rw http.ResponseWriter, r *http.Request) *http.Response {
	proxy, err := m.getProxyForRequest(r)
	if err != nil {
		return m.defaultProxy.ServeHTTPForCache(rw, r)
	}

	return proxy.ServeHTTPForCache(rw, r)
}

func (m *MultiTargetProxy) CopyResponse(dst io.Writer, src io.Reader) {
	m.defaultProxy.CopyResponse(dst, src)
}

func (m *MultiTargetProxy) Init(spec *APISpec) error {
	m.VersionProxyMap = make(map[string]*ReverseProxy)
	m.specReference = spec

	remote, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "multi-target",
		}).Error("Couldn't parse default target URL in MultiTarget: ", err)
	}
	m.defaultProxy = TykNewSingleHostReverseProxy(remote, spec)
	m.defaultProxy.Init(spec)

	for versionName, versionData := range spec.VersionData.Versions {
		if versionData.OverrideTarget == "" {
			log.WithFields(logrus.Fields{
				"prefix": "multi-target",
			}).Info("----> Version ", versionName, " has no override target")
			m.VersionProxyMap[versionName] = m.defaultProxy
		} else {
			versionRemote, err := url.Parse(versionData.OverrideTarget)
			log.WithFields(logrus.Fields{
				"prefix": "multi-target",
			}).Info("----> Version ", versionName, " has '", versionData.OverrideTarget, "' for override target")
			log.WithFields(logrus.Fields{
				"prefix": "multi-target",
			}).Debug("Multi-target URL: ", versionData.OverrideTarget)
			log.WithFields(logrus.Fields{
				"prefix": "multi-target",
			}).Debug("Multi-target URL (obj): ", versionRemote)
			if err != nil {
				log.WithFields(logrus.Fields{
					"prefix": "multi-target",
				}).Error("Couldn't parse version target URL in MultiTarget: ", err)
			}
			versionProxy := TykNewSingleHostReverseProxy(versionRemote, spec)
			versionProxy.Init(spec)
			m.VersionProxyMap[versionName] = versionProxy
		}
	}
	return nil
}
