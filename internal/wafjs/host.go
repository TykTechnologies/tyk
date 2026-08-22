package wafjs

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/dop251/goja"
)

// Engine ABI constants. The host binds the canonical ruleset JSON to one
// global and requires the engine program to define one callable inspection
// entry point receiving (transaction, snapshot).
const (
	// entryPointName is the single inspection entry point the engine
	// artifact must define on the runtime global object.
	entryPointName = "wafjsInspect"
	// rulesetBindingName is the global the host binds the ruleset artifact
	// to before the engine program runs.
	rulesetBindingName = "wafjsRuleset"
)

// Host owns the WAF engine for one API. Build validates and compiles the
// pinned artifacts once per API load, Inspect runs one inspection on a
// fresh WAF-owned Goja runtime with fresh transaction state, and Close
// deactivates the engine. All three methods are safe for concurrent use;
// methods must be called on a *Host obtained from NewHost and never on a
// copy.
type Host struct {
	state atomic.Pointer[engineState]
}

// NewHost returns an inactive engine host. It holds no runtime until the
// first successful Build.
func NewHost() *Host {
	return &Host{}
}

// engineState is one compiled engine generation. Programs are immutable and
// safe to run on any number of fresh runtimes concurrently.
type engineState struct {
	engineProgram  *goja.Program
	rulesetProgram *goja.Program
}

// newVM creates a fresh WAF-owned runtime with the ruleset bound and the
// engine program evaluated. The runtime exposes no host capability beyond
// ECMAScript built-ins and the two ABI globals.
func (s *engineState) newVM() (*goja.Runtime, error) {
	vm := goja.New()
	if _, err := vm.RunProgram(s.rulesetProgram); err != nil {
		return nil, err
	}
	if _, err := vm.RunProgram(s.engineProgram); err != nil {
		return nil, err
	}
	return vm, nil
}

// Build loads and validates the pinned engine and ruleset artifacts,
// compiles them once, verifies the engine ABI on a fresh WAF-owned runtime,
// and atomically activates the result. A failed Build leaves the previously
// active engine running unchanged.
func (h *Host) Build(ctx context.Context, cfg Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return newFailure(FailureKindDeadline, "", "context_cancelled", err)
	}
	if f := cfg.validate(); f != nil {
		return f
	}

	engineArt, f := loadEngineArtifact(cfg)
	if f != nil {
		return f
	}
	_, rulesLiteral, f := loadRulesetArtifact(cfg)
	if f != nil {
		return f
	}

	rulesetProgram, err := goja.Compile("wafjs:ruleset",
		fmt.Sprintf("globalThis.%s = %s;", rulesetBindingName, rulesLiteral), false)
	if err != nil {
		return newFailure(FailureKindBuild, FailureSourceCompile, "ruleset_compile", err)
	}
	engineProgram, err := goja.Compile("wafjs:engine", engineArt.Javascript, false)
	if err != nil {
		return newFailure(FailureKindBuild, FailureSourceCompile, "engine_compile", err)
	}

	st := &engineState{engineProgram: engineProgram, rulesetProgram: rulesetProgram}
	verifyVM, err := st.newVM()
	if err != nil {
		return newFailure(FailureKindBuild, FailureSourceCompile, "engine_evaluation", err)
	}
	entryVal := verifyVM.Get(entryPointName)
	if entryVal == nil || goja.IsUndefined(entryVal) {
		return newFailure(FailureKindBuild, FailureSourceABI, "entry_point_missing", nil)
	}
	if _, ok := goja.AssertFunction(entryVal); !ok {
		return newFailure(FailureKindBuild, FailureSourceABI, "entry_point_not_callable", nil)
	}

	h.state.Store(st)
	return nil
}

// Inspect runs one request inspection. Each call gets a fresh transaction
// and a fresh runtime; no runtime or transaction state is shared between
// requests. It returns the documented Finding or a typed *Failure.
func (h *Host) Inspect(ctx context.Context, snap RequestSnapshot) (finding Finding, err error) {
	st := h.state.Load()
	if st == nil {
		return Finding{}, newFailure(FailureKindPool, "", "engine_not_active", nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Finding{}, newFailure(FailureKindDeadline, "", "context_cancelled", err)
	}
	if f := snap.validate(); f != nil {
		return Finding{}, f
	}

	// A panic anywhere in the host or engine never reaches the gateway.
	defer func() {
		if r := recover(); r != nil {
			finding = Finding{}
			err = newFailure(FailureKindInternal, "", "panic_contained", fmt.Errorf("%v", r))
		}
	}()

	vm, err := st.newVM()
	if err != nil {
		return Finding{}, newFailure(FailureKindJavaScript, "", "engine_setup", err)
	}
	entry, ok := goja.AssertFunction(vm.Get(entryPointName))
	if !ok {
		return Finding{}, newFailure(FailureKindJavaScript, "", "entry_point_not_callable", nil)
	}

	tx := vm.NewObject()
	snapObj, f := snap.toJS(vm)
	if f != nil {
		return Finding{}, f
	}

	result, err := entry(goja.Undefined(), tx, snapObj)
	if err != nil {
		return Finding{}, newFailure(FailureKindJavaScript, "", "engine_threw", err)
	}
	return decodeFinding(result)
}

// Close deactivates the engine. In-flight inspections finish on the state
// they loaded; new inspections fail with a pool failure until the next
// successful Build. Close is idempotent.
func (h *Host) Close() error {
	h.state.Store(nil)
	return nil
}
