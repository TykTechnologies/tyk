package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/lonelycode/tykcommon"
	"io"
	"net"
	"net/http"
	"strings"
)

func websocketProxy(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, "Error contacting backend server.", 500)
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Printf("Error dialing websocket backend %s: %v", target, err)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Not a hijacker?", 500)
			return
		}
		nc, _, err := hj.Hijack()
		if err != nil {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Printf("Hijack error: %v", err)
			return
		}
		defer nc.Close()
		defer d.Close()

		err = r.Write(d)
		if err != nil {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Printf("Error copying request to target: %v", err)
			return
		}

		errc := make(chan error, 2)
		cp := func(dst io.Writer, src io.Reader) {
			_, err := io.Copy(dst, src)
			errc <- err
		}
		go cp(d, nc)
		go cp(nc, d)

		<-errc
	})
}

func isWebsocket(req *http.Request) bool {
	conn_hdr := ""
	conn_hdrs := req.Header["Connection"]
	if len(conn_hdrs) > 0 {
		conn_hdr = conn_hdrs[0]
	}

	upgrade_websocket := false
	if strings.ToLower(conn_hdr) == "upgrade" {
		upgrade_hdrs := req.Header["Upgrade"]
		if len(upgrade_hdrs) > 0 {
			upgrade_websocket = (strings.ToLower(upgrade_hdrs[0]) == "websocket")
		}
	}

	return upgrade_websocket
}

type WebsockethandlerMiddleware struct {
	*TykMiddleware
}

type WebsockethandlerMiddlewareConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *WebsockethandlerMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *WebsockethandlerMiddleware) GetConfig() (interface{}, error) {
	return m.Spec.APIDefinition.WebsocketOptions, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *WebsockethandlerMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	if isWebsocket(r) {
		if m.Spec.APIDefinition.Proxy.StripListenPath {
			log.Debug("Stripping: ", m.Spec.Proxy.ListenPath)
			r.URL.Path = "/" + strings.Replace(r.URL.Path, m.Spec.Proxy.ListenPath, "", 1)
			log.Debug("Upstream Path is: ", r.URL.Path)
		}

		var thisConfig tykcommon.WebsocketConfig
		thisConfig = configuration.(tykcommon.WebsocketConfig)

		p := websocketProxy(thisConfig.WebsocketTarget)
		p.ServeHTTP(w, r)
		// Pass through
		return nil, 1666
	}

	return nil, 200
}
