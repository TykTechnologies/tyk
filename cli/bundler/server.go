package bundler

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/net/context"

	"github.com/fsnotify/fsnotify"
	"github.com/justinas/alice"
	"google.golang.org/grpc"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	logrus "github.com/Sirupsen/logrus"
	coprocess "github.com/TykTechnologies/tyk-protobuf/bindings/go"
	"github.com/TykTechnologies/tyk/apidef"
)

const (
	reloadEvent        = "_reload"
	pythonServerScript = "server.py"

	grpcConnectionString = "127.0.0.1:5555"
)

// Server wraps the proxy logic.
type Server struct {
	target   *url.URL
	proxy    *httputil.ReverseProxy
	manifest *apidef.BundleManifest
	cwd      string

	grpcConn       *grpc.ClientConn
	grpcDispatcher coprocess.DispatcherClient

	Handler http.Handler
	http.RoundTripper
}

type middlewareHandler struct {
	server   *Server
	hookName string
}

type upstreamHandler struct {
	server *Server
}

func (m *middlewareHandler) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		reply, err := m.server.grpcDispatcher.Dispatch(context.Background(), &coprocess.Object{
			HookName: m.hookName,
			Request:  &coprocess.MiniRequestObject{},
			Spec:     map[string]string{"APIID": "test"},
		})
		if err != nil {
			logrus.WithError(err).Errorf("Hook '%s' failed", m.hookName)
			h.ServeHTTP(writer, request)
			return
		}
		logrus.Infof("Hook '%s' called", m.hookName)

		// Inject headers:
		for k, v := range reply.Request.SetHeaders {
			request.Header.Set(k, v)
		}
		h.ServeHTTP(writer, request)
	})
}

func (s *Server) middlewareHandler(hookName string) *middlewareHandler {
	return &middlewareHandler{hookName: hookName, server: s}
}

func (h *upstreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.server.proxy.ServeHTTP(w, r)
	logrus.Info("Proxy replies")
}

// RoundTrip executes the request.
func (s *Server) RoundTrip(req *http.Request) (*http.Response, error) {
	logrus.Info("Sending request to upstream")
	// Rewrite host:
	req.Host = s.target.Host
	res, err := s.RoundTripper.RoundTrip(req)
	if err != nil {
		body := ioutil.NopCloser(bytes.NewReader([]byte("HTTP error")))
		return &http.Response{
			Body:       body,
			StatusCode: 500,
		}, nil
	}
	logrus.Infof("Upstream replied with HTTP %d", res.StatusCode)
	return res, nil
}

// buildChain builds the middleware chain based on the manifest.
func (s *Server) buildMiddlewareChain() error {
	logrus.Info("Building middleware chain")
	chain := alice.New()

	// Load hooks:
	preHooks := alice.New()
	for _, def := range s.manifest.CustomMiddleware.Pre {
		handler := s.middlewareHandler(def.Name)
		preHooks = preHooks.Append(handler.Handler)
	}
	chain = chain.Extend(preHooks)

	authCheckDef := s.manifest.CustomMiddleware.AuthCheck
	if authCheckDef.Name != "" {
		handler := s.middlewareHandler(authCheckDef.Name)
		chain = chain.Append(handler.Handler)
	}

	postHooks := alice.New()
	for _, def := range s.manifest.CustomMiddleware.Post {
		handler := s.middlewareHandler(def.Name)
		postHooks = postHooks.Append(handler.Handler)
	}
	chain = chain.Extend(postHooks)

	h := &upstreamHandler{server: s}
	s.Handler = chain.Then(h)
	return nil
}

func (s *Server) setupGRPC() (err error) {
	s.grpcConn, err = grpc.Dial(grpcConnectionString, grpc.WithInsecure())
	if err != nil {
		return err
	}
	s.grpcDispatcher = coprocess.NewDispatcherClient(s.grpcConn)
	return nil
}

func (s *Server) setupWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.Error(err)
	}
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					s.triggerReload()
				}
			case err := <-watcher.Errors:
				logrus.Error(err)
			}
		}
	}()
	for _, f := range s.manifest.FileList {
		fullPath := filepath.Join(s.cwd, f)
		err = watcher.Add(fullPath)
		if err != nil {
			logrus.Errorf("Couldn't watch %s", fullPath)
		}
	}
	return nil
}

func (s *Server) triggerReload() {
	logrus.Info("Triggering reload")
	reloadMessage := &coprocess.Object{
		HookName: reloadEvent,
	}
	s.grpcDispatcher.Dispatch(context.Background(), reloadMessage)
}

func (s *Server) startPython() (err error) {
	_, filename, _, _ := runtime.Caller(0)
	serverPath := filepath.Dir(filename)
	scriptPath := filepath.Join(serverPath, "python", pythonServerScript)
	cmd := exec.Command("python3", scriptPath, s.cwd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	return err
}

// NewServer parses the upstream URL and initializes a httputil.ReverseProxy.
func NewServer(upstreamURL string, manifest *apidef.BundleManifest) (server *Server, err error) {
	logrus.Infof("Initializing proxy for '%s'", upstreamURL)

	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(u)
	server = &Server{
		target:   u,
		proxy:    reverseProxy,
		manifest: manifest,
	}

	// This is for the upstream interaction:
	server.RoundTripper = http.DefaultTransport
	reverseProxy.Transport = server

	server.cwd, err = os.Getwd()
	if err != nil {
		return server, err
	}

	logrus.Infof("Working directory is: %s", server.cwd)

	err = server.startPython()
	if err != nil {
		return server, err
	}

	// Setup gRPC connection and middleware chain:
	err = server.setupGRPC()
	if err != nil {
		return server, err
	}
	err = server.setupWatcher()
	if err != nil {
		return server, err
	}
	err = server.buildMiddlewareChain()
	if err != nil {
		return server, err
	}
	return server, err
}

func (s *Server) Start(ctx *kingpin.ParseContext) error {
	return nil
}
