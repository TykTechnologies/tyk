package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/sirupsen/logrus"
)

// GojaJSVM is a goja-based JavaScript VM that uses a fresh runtime per
// execution for full concurrency safety. Pre-compiled programs are replayed
// onto each new runtime to amortise parse cost.
type GojaJSVM struct {
	Spec    *APISpec
	Timeout time.Duration
	Log     *logrus.Entry  `json:"-"`
	RawLog  *logrus.Logger `json:"-"`
	Gw      *Gateway       `json:"-"`

	programs    []*goja.Program // compiled JS programs replayed on each new runtime
	initialized bool
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
func (j *GojaJSVM) VM() interface{} {
	if !j.initialized {
		return nil
	}
	// Return a non-nil sentinel so callers that check VM() != nil pass.
	return j
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

	// Replay compiled programs (middleware definitions, coreJS, etc.)
	// Programs only define functions/prototypes — no API calls at top level.
	for _, p := range j.programs {
		if _, err := vm.RunProgram(p); err != nil {
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
func (j *GojaJSVM) LoadScript(src string) error {
	p, err := goja.Compile("", src, false)
	if err != nil {
		return err
	}
	j.programs = append(j.programs, p)
	return nil
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
	j.programs = append(j.programs, p)

	// Load user's TykJS on top, if any
	if path := gw.GetConfig().TykJSPath; path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			p, err := goja.Compile(path, string(data), false)
			if err != nil {
				logger.WithError(err).Error("Could not compile user's TykJS")
			} else {
				j.programs = append(j.programs, p)
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
		j.programs = append(j.programs, tykJsResp)
	}

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
	_ = vm.Set("log", capture)
	_ = vm.Set("rawlog", capture)
	return vm
}

func (j *GojaJSVM) DeInit() {
	j.Spec = nil
	j.Log = nil
	j.RawLog = nil
	j.Gw = nil
	j.initialized = false
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
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
		j.programs = append(j.programs, p)
	}
}

func (j *GojaJSVM) registerAPI(vm *goja.Runtime) {
	h := &JSVMAPIHelper{Spec: j.Spec, Gw: j.Gw, Log: j.Log, RawLog: j.RawLog}

	set := func(name string, fn interface{}) {
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
	set("TykBatchRequest", func(call goja.FunctionCall) goja.Value {
		result, err := h.BatchRequest(call.Argument(0).String())
		if err != nil {
			return goja.Undefined()
		}
		return vm.ToValue(result)
	})
}
