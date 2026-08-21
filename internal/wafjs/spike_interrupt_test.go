package wafjs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file is the throwaway capability spike required by the WAF-JS plan
// (bead goja-capability-map-interrupt-spike). It produces evidence, it is not
// a product behavioural contract. The recorded findings and primary-source
// citations live in docs/dev/program/waf-js/goja-capability-map.md.

// spikeCeiling is the interrupt ceiling under evaluation. It is a spike
// parameter only; it is not an approved product default.
const spikeCeiling = 100 * time.Millisecond

// spikeBoundSlack absorbs timer and scheduler noise when asserting that a
// match loop is bounded near the ceiling. It is orders of magnitude below the
// unbounded durations the spike must distinguish.
const spikeBoundSlack = 400 * time.Millisecond

// spikeCalibrationFloor is the minimum duration a single uninterrupted
// pathological match must reach before the interrupted measurement is taken;
// five times the ceiling makes the bound or unbound conclusion insensitive to
// machine noise.
const spikeCalibrationFloor = 5 * spikeCeiling

const spikeInterruptReason = "wafjs-spike-interrupt"

// pinnedEngineModules records the engine pins this spike's evidence is valid
// for. They match the Gateway go.mod and goja's own go.mod at this pin.
var pinnedEngineModules = map[string]string{
	"github.com/dop251/goja":     "v0.0.0-20241024094426-79f3a7efcdbd",
	"github.com/dlclark/regexp2": "v1.11.4",
}

// spikeLoopScript never terminates on its own; each iteration performs one
// short regexp2-backed match. The lookahead in the pattern is incompatible
// with RE2, so goja compiles it onto the dlclark/regexp2 backtracking engine
// exactly like the CRS patterns that rely on lookaheads.
const spikeLoopScript = `
	var re = /(?=x)x+[a-z]/;
	var s = 'xxxxxxxxxxxxxxxxxxxxa';
	for (;;) {
		re.test(s);
	}
`

// spikeSingleMatchScript performs exactly one pathological regexp2 match.
// ^(a+)+(?=$) against 'a'*N + 'b' sweeps exponentially many partitions of the
// a-run before returning false. The lookahead is required only to keep the
// pattern off RE2, where the same input matches in linear time.
const spikeSingleMatchScript = `
	var re = /^(a+)+(?=$)/;
	re.test(subject);
	true;
`

// TestSpikeInterruptBoundsRegexMatchLoop proves that vm.Interrupt bounds a
// JavaScript loop of regexp2 matches fired within the ceiling (plus noise).
func TestSpikeInterruptBoundsRegexMatchLoop(t *testing.T) {
	vm := goja.New()
	timer := time.AfterFunc(spikeCeiling, func() { vm.Interrupt(spikeInterruptReason) })
	defer timer.Stop()

	start := time.Now()
	_, err := vm.RunString(spikeLoopScript)
	elapsed := time.Since(start)

	var interrupted *goja.InterruptedError
	require.ErrorAs(t, err, &interrupted,
		"the match loop must end with goja's InterruptedError")
	assert.Equal(t, spikeInterruptReason, interrupted.Value(),
		"the interrupt reason must round-trip through InterruptedError")

	assert.Less(t, elapsed, spikeCeiling+spikeBoundSlack,
		"a loop of short regexp2 matches must stay bounded near the ceiling")
	t.Logf("spike evidence: match loop bounded: ceiling=%s elapsed=%s overshoot=%s",
		spikeCeiling, elapsed, elapsed-spikeCeiling)
}

// TestSpikeInterruptDoesNotPreemptInflightRegexp2Match records whether
// vm.Interrupt can bound a single in-flight regexp2 backtracking match. The
// engine's documented semantics (runtime.go Interrupt at the pinned commit:
// "it does not interrupt native Go functions (which includes all built-ins)")
// predict that the pending interrupt is observed only after the match runs to
// completion. The test asserts and records that measured outcome.
func TestSpikeInterruptDoesNotPreemptInflightRegexp2Match(t *testing.T) {
	subject, baseline := calibratePathologicalSubject(t)

	vm := goja.New()
	require.NoError(t, vm.Set("subject", subject))
	timer := time.AfterFunc(spikeCeiling, func() { vm.Interrupt(spikeInterruptReason) })
	defer timer.Stop()

	start := time.Now()
	_, err := vm.RunString(spikeSingleMatchScript)
	elapsed := time.Since(start)

	var interrupted *goja.InterruptedError
	require.ErrorAs(t, err, &interrupted,
		"the interrupt must eventually surface as InterruptedError")

	// The interrupt was pending from the ceiling onward; if it had preempted
	// the match, elapsed would sit near the ceiling. It does not.
	assert.Greater(t, elapsed, 3*spikeCeiling,
		"a single in-flight regexp2 match must be shown to overrun the ceiling")
	// The match ran essentially to completion rather than being cut short:
	// the interrupted duration is at least half the uninterrupted baseline.
	assert.Greater(t, elapsed, baseline/2,
		"the in-flight match must be shown to run to completion")
	t.Logf("spike evidence: single regexp2 match not preempted: ceiling=%s baseline=%s elapsed_with_interrupt=%s overrun=%s",
		spikeCeiling, baseline, elapsed, elapsed-spikeCeiling)
}

// TestSpikePinnedEngineModules confirms from the Gateway go.mod that the
// goja and regexp2 versions the spike measured are the pinned ones.
func TestSpikePinnedEngineModules(t *testing.T) {
	found := pinnedModuleVersions(t, moduleGoModPath(t))

	for path, want := range pinnedEngineModules {
		assert.Equalf(t, want, found[path],
			"engine pin for %s differs from the recorded pin; the capability map evidence is valid only at the recorded pin", path)
	}
	t.Logf("benchmark environment engine version: github.com/dop251/goja %s (github.com/dlclark/regexp2 %s)",
		found["github.com/dop251/goja"], found["github.com/dlclark/regexp2"])
}

// moduleGoModPath locates the module's go.mod by walking up from the test's
// working directory (the package source directory under `go test`).
func moduleGoModPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		candidate := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test working directory")
		}
		dir = parent
	}
}

// pinnedModuleVersions extracts the require versions for the tracked engine
// modules from go.mod text without adding a modfile dependency.
func pinnedModuleVersions(t *testing.T, goModPath string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(goModPath)
	require.NoError(t, err)

	found := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, tracked := pinnedEngineModules[fields[0]]; tracked {
			found[fields[0]] = fields[1]
		}
	}
	return found
}

// calibratePathologicalSubject grows the pathological input until one
// uninterrupted match runs at least spikeCalibrationFloor, so the interrupted
// measurement on the returned subject is decisive on any machine speed. It
// returns the subject and its measured baseline duration.
func calibratePathologicalSubject(t *testing.T) (string, time.Duration) {
	t.Helper()
	for n := 16; n <= 34; n += 2 {
		subject := strings.Repeat("a", n) + "b"
		baseline := runSinglePathologicalMatch(t, subject, nil)
		if baseline >= spikeCalibrationFloor {
			t.Logf("spike calibration: n=%d a's, baseline single match=%s", n, baseline)
			return subject, baseline
		}
	}
	t.Fatal("could not build a subject whose single pathological match reaches the calibration floor; raise the size cap")
	return "", 0
}

// runSinglePathologicalMatch runs the single-match script once. When fireAt
// is non-nil the interrupt fires after that duration.
func runSinglePathologicalMatch(t *testing.T, subject string, fireAt *time.Duration) time.Duration {
	t.Helper()
	vm := goja.New()
	require.NoError(t, vm.Set("subject", subject))
	if fireAt != nil {
		timer := time.AfterFunc(*fireAt, func() { vm.Interrupt(spikeInterruptReason) })
		defer timer.Stop()
	}
	start := time.Now()
	_, err := vm.RunString(spikeSingleMatchScript)
	require.True(t, err == nil || errors.As(err, new(*goja.InterruptedError)),
		"unexpected script error: %v", err)
	return time.Since(start)
}
