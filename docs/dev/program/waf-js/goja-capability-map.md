# Goja capability map and interrupt spike evidence

Track: waf-js. Fulfils the WAF-JS plan step "map the current Goja request,
body, and lifecycle capabilities" and gates every later bead that depends on
an execution-time bound for regular-expression matching.

All source citations below are version-relative paths into the pinned module
sources (the local module cache copy is byte-identical to the tag; verify with
`go mod download` or pkg.go.dev at the same pseudo-version). Citations were
read on 2026-08-22. The `100 ms` ceiling in the spike is a measurement
parameter, not an approved product default.

## Engine pin and version string

| Fact | Value |
| --- | --- |
| Gateway go.mod require | `github.com/dop251/goja v0.0.0-20241024094426-79f3a7efcdbd` (go.mod:104) |
| Regexp fallback require | `github.com/dlclark/regexp2 v1.11.4` (go.mod:296, indirect via goja) |
| goja's own go.mod | requires `github.com/dlclark/regexp2 v1.11.4` (goja go.mod:7); the resolved version equals goja's own requirement at this pin |
| Module listing (command receipt) | `go list -m github.com/dop251/goja github.com/dlclark/regexp2` → the two versions above |
| Engine version string for the benchmark environment block | `goja v0.0.0-20241024094426-79f3a7efcdbd (regexp2 v1.11.4)` |
| Pinning rule | The pin changes only through the recorded dependency-provenance rule (AGENTS.md); no version was changed for this spike |

## Capability map

| # | Design dependency | Status | Primary-source evidence at the pin | Consequence |
| --- | --- | --- | --- | --- |
| 1 | ECMAScript level | Confirmed: full ES5.1, partial ES6 | README.md:4,8 ("ECMAScript 5.1(+) implementation"); README.md:18-23 (full ES5.1 incl. regex and strict mode; passes nearly all tc39 test262 for implemented features; "Most of ES6 functionality, still work in progress") | Generated WAF JavaScript targets ES5.1 plus the ES6 subset goja implements; any newer syntax the generator emits must be feature-checked at this pin |
| 2 | ArrayBuffer/Uint8Array over Go bytes, no string conversion | Confirmed, zero-copy | `Runtime.NewArrayBuffer(data []byte) ArrayBuffer` stores the slice directly (`typedarrays.go:116-128`); `ArrayBuffer.Bytes()` returns the same slice (`typedarrays.go:92-96`); `new Uint8Array(ab)` creates a view sharing `viewedArrayBuf` (`builtin_typedarrays.go:1442-1471`; element access via the shared `uint8Array []byte` slice, `typedarrays.go:60,130-153`) | Request bodies can reach JS as an exact binary-safe representation; Go-side mutation through the view is visible without copies or UTF-8 sanitisation |
| 3 | TextDecoder/TextEncoder | Absent at this pin | No `TextDecoder`/`TextEncoder` symbols anywhere in the goja module sources at the pin | Recorded fallback: byte→string views (when the WAF needs them) must be JS-side or Go-registered helpers; they are not engine built-ins |
| 4 | RegExp engine selection | Confirmed: dual engine | `compileRegexp` tries `parser.TransformRegExp` first and compiles the result on Go's RE2 (`builtin_regexp.go:185-290`); a `RegexpErrorIncompatible` — lookahead `(?=`/`(?!)`, lookbehind `(?<`, backreference (`parser/regexp.go:48-57`, `parser/regexp.go:168-185`, error mapping at `parser/regexp.go:457-469`) — falls back to `compileRegexp2` (regexp2 with `regexp2.ECMAScript` options, `regexp.go:70-90`). Some runtime paths also switch to regexp2 lazily, e.g. matches starting at a non-zero offset (`regexp.go:126-138`) and several unicode/global paths (`regexp.go:140-175`) | CRS patterns bearing lookaheads/backreferences (common in the 941/942 families) evaluate on the backtracking regexp2 engine; RE2's linear-time guarantee does not apply to them |
| 5 | Per-match time bound on regexp2 | NOT met by engine defaults | regexp2 `DefaultMatchTimeout = time.Duration(math.MaxInt64)` ("forever", `regexp2@v1.11.4/regexp.go:22-36`, constructor default at `regexp2@v1.11.4/regexp.go:78`); goja's `compileRegexp2` never sets `MatchTimeout` (`regexp.go:70-90`) | A single catastrophic-backtracking match is unbounded by construction at this pin; see spike verdict |
| 6 | `vm.Interrupt` semantics | Confirmed, with a hard limit | `Runtime.Interrupt` doc: "Interrupt a running JavaScript … it only works while in JavaScript code, it does not interrupt native Go functions (which includes all built-ins)" (`runtime.go:1508-1513`); the flag is polled in the VM bytecode dispatch loop (`vm.go:621` in `func (vm *vm) run()`, and `vm.go:654`); `ClearInterrupt()` is required before runtime reuse (`runtime.go:1518-1525`) | Interrupt bounds JavaScript-level loops (including loops of regexp calls) but cannot preempt one in-flight native regexp match; measured below |
| 7 | `JSON.parse` on malformed UTF-8 | Confirmed lossy, no throw | `builtinJSON_parse` decodes through Go `encoding/json` over the UTF-8 string form (`builtin_json.go:20-21`); README caveat: because it operates in UTF-8 it cannot correctly parse broken UTF-16 surrogate pairs, which come back as U+FFFD (`README.md:58-64`, example `JSON.parse('"\\uD800"').charCodeAt(0)` → `fffd`) | Malformed encodings normalise to U+FFFD instead of erroring; rule evaluation on JSON bodies must treat U+FFFD substitution as expected behaviour, and evasion analysis must account for it |
| 8 | Runtime concurrency model | Confirmed | README.md:99-103: a `goja.Runtime` is usable by one goroutine at a time; fresh runtimes cannot share object values | Matches the Gateway's fresh-runtime-per-request model in `gateway/mw_js_plugin_goja.go`; per-request runtimes remain the WAF shape |
| 9 | Engine version string for benchmarks | Recorded | `TestSpikePinnedEngineModules` asserts the pins from go.mod and logs the version string | Benchmark environment blocks cite `goja v0.0.0-20241024094426-79f3a7efcdbd (regexp2 v1.11.4)` |

## Interrupt spike: what was measured

Retained as tests in `internal/wafjs/spike_interrupt_test.go` (throwaway
spike, evidence-producing; run with `go test -count=1 ./internal/wafjs/`).

Method: start a goja runtime at the pinned version, run pathological
JavaScript regular-expression work, fire `vm.Interrupt` after a 100 ms
ceiling, and measure the duration of the `RunString` call that returns the
`*goja.InterruptedError`.

- **Match loop** — `for (;;) { re.test(s) }` with `/(?=x)x+[a-z]/` (lookahead
  forces the regexp2 engine, as capability 4 documents).
- **Single in-flight match** — one `re.test(subject)` with
  `/^(a+)+(?=$)/` against `'a'*N + 'b'`; the subject is calibrated per machine
  until the uninterrupted match runs at least 500 ms (5x the ceiling), so the
  result is decisive independent of machine speed.

Measured on 2026-08-22, darwin/arm64 (Apple silicon), go1.26.5,
`go test -count=1 ./internal/wafjs/`:

| Measurement | Result |
| --- | --- |
| Match loop, ceiling 100 ms | `InterruptedError` after 100.5 ms (overshoot 0.5 ms) — **bounded** |
| Single match baseline (calibrated N=24) | 1.73 s uninterrupted |
| Single match with interrupt at 100 ms | `InterruptedError` after 1.90 s (overrun 1.80 s beyond the ceiling; the match ran to completion) — **not bounded** |

The run-to-completion outcome is what the engine documents (capability 6):
`RegExp.prototype.test` is a native Go built-in; the interrupt flag is polled
only between bytecode instructions, and regexp2's own `MatchTimeout` is
infinite (capability 5).

## Verdict and owner decision

**Partially bounded.** `vm.Interrupt` bounds JavaScript-level work — loops,
rule iteration, repeated short matches — within the ceiling plus scheduler
noise. It does **not** bound a single in-flight regexp2 backtracking match,
which is exactly the DoS shape CRS evaluation creates: attacker-controlled
subject bytes evaluated against lookahead/backreference-bearing CRS patterns
that goja compiles onto regexp2 with no match timeout.

Per the bead contract (`goja-capability-map-interrupt-spike`):

- No fallback has been selected. In particular, no native Go/RE2 matcher and
  no unbounded worker arrangement was chosen or implemented.
- Work that relies on an execution-time bound for a single regexp2 match
  stops here for an owner decision. The decision must cover how such matches
  are bounded (or otherwise handled) before any later bead assumes a total
  request-inspection time bound from `vm.Interrupt` alone.
- The 100 ms ceiling is a spike parameter; it is not an approved product
  default.

## Dependency impact

- No dependency was added, removed, or upgraded. `go.mod` and `go.sum` are
  unchanged; `go list -m all` remains byte-identical to the recorded baseline
  from `crs-pin-provenance.md`.
- The spike imports only modules already required by the Gateway
  (`github.com/dop251/goja` direct; `github.com/stretchr/testify` test).
