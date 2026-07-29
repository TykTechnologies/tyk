package gateway

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/storage"
)

// GojaJSVM is a goja-based JavaScript VM that uses a fresh runtime per
// execution for full concurrency safety. Pre-compiled programs are replayed
// onto each new runtime to amortise parse cost.
//
// Middleware programs are wrapped at compile time in an IIFE (see
// wrapMiddlewareSource) so each plugin's `var` declarations stay local to
// its closure. Each named handler is exposed under a deterministic global
// alias derived from (file path, manifest name); dispatch invokes the alias
// rather than the original name. This lets multiple files — and multiple
// bundles, when CustomMiddlewareBundle is a comma-separated list — declare handlers under
// the same JS-side name without colliding with each other's globals or
// breaking closures that reference the var lexically.
type GojaJSVM struct {
	Spec    *APISpec
	Timeout time.Duration
	Log     *logrus.Entry  `json:"-"`
	RawLog  *logrus.Logger `json:"-"`
	Gw      *Gateway       `json:"-"`

	programs    []gojaProgram // compiled JS programs replayed on each new runtime
	store       *storage.RedisCluster
	initialized bool
}

// gojaProgram pairs a compiled program with the path under which it was
// loaded. Path is empty for support scripts (coreJS, TykJsResponse helper,
// user TykJSPath library) — those are not wrapped and their globals stay
// reachable under their original names.
type gojaProgram struct {
	p    *goja.Program
	path string
}

// Initialized reports whether the GojaJSVM has been set up.
func (j *GojaJSVM) Initialized() bool {
	return j.initialized
}

// Ready implements JSRunner.
func (j *GojaJSVM) Ready() bool {
	return j.initialized
}

// VM returns nil — goja does not have a persistent VM; a fresh runtime is
// created per Run() call.  This satisfies call-sites that guard on VM != nil.
func (j *GojaJSVM) VM() any {
	if !j.initialized {
		return nil
	}
	// Return a non-nil sentinel so callers that check VM() != nil pass.
	return j
}

// AliasFor returns the deterministic global name a middleware handler is
// exposed under inside the goja runtime. Dispatch must use this name (not
// the original `name` from the manifest) when constructing dispatch
// expressions for goja-driven plugins.
//
// AliasFor is pure — its output is a function of its inputs alone.
func (j *GojaJSVM) AliasFor(path, name string) string {
	return gojaHandlerAlias(path, name)
}

// newRuntime creates a fresh goja runtime with all loaded programs and Go API functions.
func (j *GojaJSVM) newRuntime() *goja.Runtime {
	vm := goja.New()

	// Suppress top-level log() calls during program replay.
	nop := func(_ goja.FunctionCall) goja.Value { return goja.Undefined() }
	if err := vm.Set("log", nop); err != nil && j.Log != nil {
		j.Log.WithError(err).Error("Failed to suppress log during replay")
	}
	if err := vm.Set("rawlog", nop); err != nil && j.Log != nil {
		j.Log.WithError(err).Error("Failed to suppress rawlog during replay")
	}

	// Replay compiled programs. Middleware programs are pre-wrapped at
	// compile-time in an IIFE that scopes each plugin's `var` declarations
	// locally and exposes only its handler under the per-(path, name) alias.
	// This isolation lets multiple files (or multiple bundles) declare the
	// same handler name (e.g. `var handler = ...`) without overwriting each
	// other's globals AND without breaking closures that reference the var
	// lexically — see wrapMiddlewareSource for the codegen.
	for _, lp := range j.programs {
		if _, err := vm.RunProgram(lp.p); err != nil {
			if j.Log != nil {
				j.Log.WithError(err).Error("Failed to replay JS program")
			}
		}
	}

	// Register Go API functions (b64, HTTP, key CRUD, log, rawlog).
	// This overwrites the nop log/rawlog with real ones for request execution.
	j.registerAPI(vm)

	return vm
}

// Run executes a JS expression on a fresh runtime with timeout handling.
// Each call gets an isolated runtime so concurrent requests don't interfere.
func (j *GojaJSVM) Run(expr string) (string, error) {
	if !j.initialized {
		return "", errors.New("JSVM isn't enabled, check your gateway settings")
	}

	vm := j.newRuntime()

	timer := time.AfterFunc(j.Timeout, func() {
		vm.Interrupt("timeout")
	})
	defer timer.Stop()

	returnRaw, err := vm.RunString(expr)
	if err != nil {
		var interrupted *goja.InterruptedError
		if errors.As(err, &interrupted) {
			return "", fmt.Errorf("JS middleware timed out after %v", j.Timeout)
		}
		return "", err
	}

	return returnRaw.String(), nil
}

// LoadScript compiles a JS source string and adds it to the programs list.
// Used for support scripts (no path, no aliases). For middleware code with
// known (path, names), use LoadInlineMiddleware.
func (j *GojaJSVM) LoadScript(src string) error {
	p, err := goja.Compile("", src, false)
	if err != nil {
		return err
	}
	j.programs = append(j.programs, gojaProgram{p: p})
	return nil
}

// LoadInlineMiddleware compiles inline middleware source under the given
// synthetic path key. The source is wrapped in an IIFE that scopes its `var`
// declarations and exposes each named handler under a per-(path, name)
// global alias. Dispatch must use the alias (via AliasFor); the original
// names are never written to globalThis.
//
// path must be unique across the JSVM; callers should construct it from
// (apiID, hook, index) or similar to avoid collisions with sibling inline
// middleware.
func (j *GojaJSVM) LoadInlineMiddleware(path, src string, names []string) error {
	wrapped := wrapMiddlewareSource(path, src, names)
	p, err := goja.Compile(path, wrapped, false)
	if err != nil {
		return err
	}
	j.programs = append(j.programs, gojaProgram{p: p, path: path})
	return nil
}

// LoadMiddlewareFile reads a JS file from disk and registers it as middleware
// with handler-name isolation. Used by api_loader for file-mount and bundle
// modes (one file at a time, with the manifest's name and path).
func (j *GojaJSVM) LoadMiddlewareFile(path string, names []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return j.LoadInlineMiddleware(path, string(data), names)
}

// wrapMiddlewareSource wraps user JS in an IIFE so its `var` declarations are
// local to the closure rather than top-level globals. The IIFE explicitly
// captures each named handler into globalThis under its unique per-(path,
// name) alias, which is the identifier dispatch will look up at request time.
//
// The `typeof` guard avoids ReferenceError if the plugin's source declares
// fewer handlers than its manifest claims (broken plugin → silent skip,
// surfaced later as a dispatch lookup miss).
func wrapMiddlewareSource(path, src string, names []string) string {
	if len(names) == 0 {
		return src
	}
	var assignments strings.Builder
	for _, n := range names {
		if n == "" {
			continue
		}
		alias := gojaHandlerAlias(path, n)
		fmt.Fprintf(&assignments, "if (typeof %s !== 'undefined') { globalThis[%q] = %s; }\n", n, alias, n)
	}
	return "(function () {\n" + src + "\n;\n" + assignments.String() + "})();\n"
}

const defaultGojaJSVMTimeout = 5

// Init creates the GojaJSVM with the core library and sets up a default timeout.
func (j *GojaJSVM) Init(spec *APISpec, logger *logrus.Entry, gw *Gateway) {
	j.Gw = gw
	j.programs = nil
	logger = logger.WithField("prefix", "jsvm-goja")

	// Compile and store coreJS
	p, err := goja.Compile("coreJS", coreJS, false)
	if err != nil {
		logger.WithError(err).Error("Could not compile TykJS")
		return
	}
	j.programs = append(j.programs, gojaProgram{p: p})

	// Load user's TykJS on top, if any
	if path := gw.GetConfig().TykJSPath; path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			p, err := goja.Compile(path, string(data), false)
			if err != nil {
				logger.WithError(err).Error("Could not compile user's TykJS")
			} else {
				j.programs = append(j.programs, gojaProgram{p: p})
			}
		}
	}

	// Compile the TykJsResponse helper
	tykJsResp, err := goja.Compile("TykJsResponse", `function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	}`, false)
	if err != nil {
		logger.WithError(err).Error("Could not compile TykJsResponse")
	} else {
		j.programs = append(j.programs, gojaProgram{p: tykJsResp})
	}

	// HashKeys stays false so keys land verbatim under the enforced prefix;
	// the helper additionally prefixes on the raw client so plugin keys can
	// never escape the jsvm-store namespace.
	j.store = &storage.RedisCluster{KeyPrefix: jsvmStoreKeyPrefix, HashKeys: false, ConnectionHandler: gw.StorageConnectionHandler}

	j.Spec = spec
	j.initialized = true

	if jsvmTimeout := gw.GetConfig().JSVMTimeout; jsvmTimeout <= 0 {
		j.Timeout = time.Duration(defaultGojaJSVMTimeout) * time.Second
		logger.Debugf("Default JSVM timeout used: %v", j.Timeout)
	} else {
		j.Timeout = time.Duration(jsvmTimeout) * time.Second
		logger.Debugf("Custom JSVM timeout: %v", j.Timeout)
	}

	j.Log = logger
	j.RawLog = rawLog
}

// TestRunnerRuntime returns a fresh runtime with all programs replayed and real
// bindings registered, but with log/rawlog overridden to capture output
// into the provided slice instead of writing to logrus.
// Used by the plugin test runner (mw_js_plugin_test_runner.go).
func (j *GojaJSVM) TestRunnerRuntime(logs *[]testRunnerLog) *goja.Runtime {
	vm := j.newRuntime() // replays programs; registers real APIs including logrus-backed log
	capture := func(call goja.FunctionCall) goja.Value {
		*logs = append(*logs, testRunnerLog{
			Level:   "info",
			Message: call.Argument(0).String(),
			Time:    time.Now().UTC().Format(time.RFC3339Nano),
		})
		return goja.Undefined()
	}
	if err := vm.Set("log", capture); err != nil {
		log.WithError(err).Error("Failed to set log function in sandbox VM")
	}
	if err := vm.Set("rawlog", capture); err != nil {
		log.WithError(err).Error("Failed to set rawlog function in sandbox VM")
	}
	return vm
}

func (j *GojaJSVM) DeInit() {
	j.Spec = nil
	j.Log = nil
	j.RawLog = nil
	j.Gw = nil
	j.store = nil
	j.initialized = false
	j.programs = nil
}

// LoadJSPaths will load JS classes and functionality in to the VM by file.
// Each path is recorded so RegisterMiddlewareAliases can later associate
// handler names declared in the corresponding manifest entry.
func (j *GojaJSVM) LoadJSPaths(paths []string, prefix string) {
	for _, mwPath := range paths {
		if prefix != "" {
			mwPath = filepath.Join(prefix, mwPath)
		}
		extension := filepath.Ext(mwPath)
		if !strings.Contains(extension, ".js") {
			j.Log.Errorf("Unsupported extension '%s' (%s)", extension, mwPath)
			continue
		}
		j.Log.Info("Loading JS File: ", mwPath)
		data, err := os.ReadFile(mwPath)
		if err != nil {
			j.Log.WithError(err).Error("Failed to open JS middleware file")
			continue
		}
		p, err := goja.Compile(mwPath, string(data), false)
		if err != nil {
			j.Log.WithError(err).Error("Failed to compile JS middleware")
			continue
		}
		j.programs = append(j.programs, gojaProgram{p: p, path: mwPath})
	}
}

// gojaHandlerAlias derives a deterministic, JS-safe identifier for a handler
// declared at (path, name). The hash prefix prevents collisions across paths
// while keeping the original name suffix as a debugging aid.
func gojaHandlerAlias(path, name string) string {
	sum := sha256.Sum256([]byte(path + "::" + name))
	return fmt.Sprintf("__tyk_h_%x_%s", sum[:6], sanitizeJSIdent(name))
}

// sanitizeJSIdent replaces non-ident characters with underscores so the
// result is a legal JS identifier.
func sanitizeJSIdent(s string) string {
	if s == "" {
		return "h"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func (j *GojaJSVM) registerAPI(vm *goja.Runtime) {
	h := &JSVMAPIHelper{Spec: j.Spec, Gw: j.Gw, Log: j.Log, RawLog: j.RawLog, Store: j.store}

	set := func(name string, fn any) {
		if err := vm.Set(name, fn); err != nil && j.Log != nil {
			j.Log.WithError(err).Errorf("Failed to register JS function: %s", name)
		}
	}

	set("log", func(call goja.FunctionCall) goja.Value {
		h.LogMessage(call.Argument(0).String())
		return goja.Undefined()
	})
	set("rawlog", func(call goja.FunctionCall) goja.Value {
		h.RawLogMessage(call.Argument(0).String())
		return goja.Undefined()
	})
	set("b64dec", func(call goja.FunctionCall) goja.Value {
		out, err := h.B64Decode(call.Argument(0).String())
		if err != nil {
			return goja.Undefined()
		}
		return vm.ToValue(out)
	})
	set("b64enc", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(h.B64Encode(call.Argument(0).String()))
	})
	set("rawb64dec", func(call goja.FunctionCall) goja.Value {
		out, err := h.RawB64Decode(call.Argument(0).String())
		if err != nil {
			return goja.Undefined()
		}
		return vm.ToValue(out)
	})
	set("rawb64enc", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(h.RawB64Encode(call.Argument(0).String()))
	})
	set("TykMakeHttpRequest", func(call goja.FunctionCall) goja.Value {
		result, err := h.MakeHTTPRequest(call.Argument(0).String())
		if err != nil || result == "" {
			return goja.Undefined()
		}
		return vm.ToValue(result)
	})
	set("TykGetKeyData", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(h.GetKeyData(call.Argument(0).String(), call.Argument(1).String()))
	})
	set("TykSetKeyData", func(call goja.FunctionCall) goja.Value {
		if err := h.SetKeyData(call.Argument(0).String(), call.Argument(1).String(), call.Argument(2).String()); err != nil {
			h.Log.WithError(err).Error("Failed to set key data from JS")
		}
		return goja.Undefined()
	})
	// Storage bindings throw a JS exception on failure (Redis outage,
	// timeout, cap violation) instead of returning undefined — a plugin must
	// never be able to mistake an outage for key-absent.
	set("TykStorageGet", func(call goja.FunctionCall) goja.Value {
		val, found, err := h.StorageGet(call.Argument(0).String())
		if err != nil {
			panic(vm.NewGoError(err))
		}
		if !found {
			return goja.Null()
		}
		return vm.ToValue(val)
	})
	set("TykStorageSet", func(call goja.FunctionCall) goja.Value {
		if err := h.StorageSet(call.Argument(0).String(), call.Argument(1).String(), call.Argument(2).ToInteger()); err != nil {
			panic(vm.NewGoError(err))
		}
		return goja.Undefined()
	})
	set("TykStorageSetNX", func(call goja.FunctionCall) goja.Value {
		set, err := h.StorageSetNX(call.Argument(0).String(), call.Argument(1).String(), call.Argument(2).ToInteger())
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return vm.ToValue(set)
	})
	set("TykStorageDel", func(call goja.FunctionCall) goja.Value {
		if err := h.StorageDel(call.Argument(0).String()); err != nil {
			panic(vm.NewGoError(err))
		}
		return goja.Undefined()
	})
	set("TykStorageTTL", func(call goja.FunctionCall) goja.Value {
		ttl, err := h.StorageTTL(call.Argument(0).String())
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return vm.ToValue(ttl)
	})
	set("TykStorageIncr", func(call goja.FunctionCall) goja.Value {
		val, err := h.StorageIncr(call.Argument(0).String(), call.Argument(1).ToInteger())
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return vm.ToValue(val)
	})
	set("TykBatchRequest", func(call goja.FunctionCall) goja.Value {
		result, err := h.BatchRequest(call.Argument(0).String())
		if err != nil {
			return goja.Undefined()
		}
		return vm.ToValue(result)
	})
}
