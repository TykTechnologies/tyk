package handler

import (
	"net/http"
	"path/filepath"

	"github.com/TykTechnologies/tyk/wasm"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	proxywasm "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

type H struct {
	mw          *wasm.Config
	vm          *wasm.Wasm
	instance    *wasm.Instance
	log         *logrus.Entry
	base        *Wasm
	id          atomic.Int32
	rootContext int32
}

func New(
	vm *wasm.Wasm,
	wasmModulesPath string,
	mw *wasm.Config,
	log *logrus.Entry,
) (*H, error) {
	file := filepath.Join(wasmModulesPath, mw.Module)
	mwLog := log.WithFields(logrus.Fields{
		"middleware_name": mw.Name,
		"module_name":     filepath.Base(mw.Module),
	})

	mwLog.Info("Compiling wasm module")
	mwLog.Debug("Module path " + file)
	m, err := vm.CompileFile(file)
	if err != nil {
		return nil, err
	}
	var id atomic.Int32
	rootContext := id.Inc()
	mwLog = mwLog.WithField("rootContext", rootContext)
	mwLog.Info("Creating new wasm instance")
	instance, err := vm.NewInstance(mw, m)
	if err != nil {
		mwLog.WithError(err).Error("Failed to create wasm instance")
		return nil, err
	}
	// we start the module instance beforehand.
	mwLog.Info("Starting wasm module instance")
	err = instance.Start()
	if err != nil {
		mwLog.WithError(err).Error("Failed to start wasm instance")
		return nil, err
	}
	base := &Wasm{}
	base.L = mwLog
	bufFn, releaseBuf := safeBuffer()
	defer releaseBuf()
	base.NewBuffer = bufFn
	rootABI := &proxywasm.ABIContext{
		Imports:  base,
		Instance: instance,
	}
	export := rootABI.GetExports()
	// create root plugin context
	mwLog.Info("Creating root context")
	err = export.ProxyOnContextCreate(rootContext, 0)
	if err != nil {
		mwLog.WithError(err).Error("Failed creating root context")
		return nil, err
	}
	return &H{
		mw:          mw,
		vm:          vm,
		instance:    instance,
		log:         mwLog,
		id:          id,
		base:        base,
		rootContext: rootContext,
	}, nil
}

func (h *H) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// create a http context
		httpContextID := h.id.Inc()
		mwLog := h.log.WithField("httpContextID", httpContextID)
		ctxBuf, releaseBuffers := safeBuffer()
		defer releaseBuffers()

		abi := h.abi(
			// set request
			func(n *Wasm) {
				n.Logger.L = mwLog
				n.Request.Request = r
				n.Response.Response = w
				n.Plugin.Config = h.mw.Plugin
				n.Plugin.Instance = h.mw.Instance
				n.Plugin.NewBuffer = ctxBuf

				n.HTTPCall.log = mwLog
				n.HTTPCall.newBuffer = ctxBuf
			},
		)
		abi.Instance.Lock(abi)
		defer abi.Instance.Unlock()

		exports := abi.GetExports()
		ctx := &ExecContext{
			Log:         mwLog,
			ContextID:   httpContextID,
			RootContext: h.rootContext,
			Exports:     exports,
			Request:     r,
			Response:    w,
		}
		if err := ctx.Before(); err != nil {
			mwLog.WithError(err).Error("ProxyOnContextCreate")
			h.E500(w, r)
			return
		}
		//make sure we destroy the context when we are done
		defer func() {
			if err := ctx.After(); err != nil {
				mwLog.WithError(err).Error("ProxyOnContextFinalize")
			}
		}()
		if ctx.Apply() {
			next.ServeHTTP(w, r)
		}
	})
}

func (h *H) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	// create a http context
	httpContextID := h.id.Inc()
	mwLog := h.log.WithField("httpContextID", httpContextID)
	ctxBuf, releaseBuffers := safeBuffer()
	defer releaseBuffers()

	abi := h.abi(
		// set request
		func(n *Wasm) {
			n.Logger.L = mwLog
			n.Request.Request = r
			n.Response.Response = w
			n.Plugin.Config = h.mw.Plugin
			n.Plugin.Instance = h.mw.Instance
			n.Plugin.NewBuffer = ctxBuf

			n.HTTPCall.log = mwLog
			n.HTTPCall.newBuffer = ctxBuf
		},
	)
	abi.Instance.Lock(abi)
	defer abi.Instance.Unlock()

	exports := abi.GetExports()
	abi.Imports.(*Wasm).HTTPCall.exports = exports
	abi.Imports.(*Wasm).HTTPCall.contextID = httpContextID
	ctx := &ExecContext{
		Log:         mwLog,
		ContextID:   httpContextID,
		RootContext: h.rootContext,
		Exports:     exports,
		Request:     r,
		Response:    w,
	}
	if err := ctx.Before(); err != nil {
		mwLog.WithError(err).Error("ProxyOnContextCreate")
		return err, http.StatusInternalServerError
	}
	defer func() {
		if err := ctx.After(); err != nil {
			mwLog.WithError(err).Error("ProxyOnContextFinalize")
		}
	}()
	ctx.Apply()
	ws := abi.Imports.(*Wasm)
	return ws.GetStatusDetail(), ws.GetStatus()
}

func (h *H) abi(modify ...func(*Wasm)) *proxywasm.ABIContext {
	w := &Wasm{}
	for _, fn := range modify {
		fn(w)
	}
	return &proxywasm.ABIContext{
		Imports:  w,
		Instance: h.instance,
	}
}

func (h *H) E500(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

type ExecContext struct {
	Log         *logrus.Entry
	ContextID   int32
	RootContext int32
	Exports     proxywasm.Exports
	Request     *http.Request
	Response    http.ResponseWriter
}

func (e *ExecContext) Before() error {
	return e.Exports.ProxyOnContextCreate(
		e.ContextID, e.RootContext,
	)
}

func (e *ExecContext) Apply() (applyNext bool) {
	return e.apply(
		e.httpRequest()...,
	)
}

func (e *ExecContext) apply(fns ...applyFn) (applyNext bool) {
	for _, fn := range fns {
		action, name, err := fn()
		if err != nil {
			e.Log.WithError(err).Error(name)
			return false
		}
		if action != proxywasm.ActionContinue {
			return false
		}
	}
	return true
}

type applyFn func() (action proxywasm.Action, name string, err error)

func (e *ExecContext) After() error {
	_, err := e.Exports.ProxyOnDone(e.ContextID)
	return err
}

func (e *ExecContext) httpRequest() []applyFn {
	return []applyFn{
		func() (action proxywasm.Action, name string, err error) {
			a, err := e.Exports.ProxyOnRequestHeaders(
				e.ContextID, int32(len(e.Request.Header)), 0,
			)
			return a, "ProxyOnHttpRequestHeaders", err
		},
		func() (action proxywasm.Action, name string, err error) {
			a, err := e.Exports.ProxyOnRequestTrailers(
				e.ContextID, int32(len(e.Request.Trailer)),
			)
			return a, "ProxyOnHttpRequestTrailers", err
		},
	}
}
