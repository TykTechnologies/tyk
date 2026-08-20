# Implementation Spike: A/B Evaluation of Coraza vs JavaScript CRS WAF for Tyk

## Summary

Run two parallel implementation spikes against the same target version of Tyk and OWASP Core Rule Set (CRS):

**Track A — Native Coraza integration:** integrate Coraza directly into Tyk's Go request/response pipeline.

**Track B — JavaScript WAF:** implement a CRS-derived WAF running in the existing Goja plugin runtime, with only minimal generic changes to the Goja/security-plugin ABI where required.

The objective is not to prove either design in isolation. The objective is to produce enough working code and measurements to make an evidence-based choice between them.

Both tracks should implement the same initial WAF profile and be evaluated against the same functional, compatibility, maintainability and performance criteria.

The primary comparison should answer:

> Is the operational flexibility of a separately distributable JavaScript WAF worth the implementation and runtime complexity compared with embedding Coraza directly?

---

# Background

Tyk already provides a Goja-based JavaScript plugin runtime with access to the HTTP request/response lifecycle and Redis-backed storage.

This creates two plausible approaches to adding OWASP CRS-compatible WAF capabilities.

## Track A: Native Coraza

```text
Tyk Gateway
    │
    ▼
Coraza Go library
    │
    ▼
OWASP CRS
```

Advantages are expected to include high CRS compatibility, an existing WAF engine and relatively little WAF-specific implementation work.

The main trade-off is that Coraza becomes part of the Gateway binary and WAF engine changes require rebuilding/releasing the Gateway.

---

## Track B: JavaScript WAF

```text
Tyk Gateway
    │
    ├── small generic Goja/security capabilities
    │
    ▼
Goja
    │
    ├── JS WAF runtime
    ├── generated CRS rules
    ├── body processors
    └── attack detection
```

The expected advantage is that the WAF implementation and future CRS releases can be distributed independently from the Gateway binary.

The expected trade-offs are more implementation code, incomplete CRS compatibility initially, and additional Goja runtime overhead.

---

# Spike methodology

The two implementations should be developed in parallel by separate agents/engineers.

Where practical, neither implementation should reuse code or assumptions from the other beyond the common acceptance criteria and test corpus.

This is intentional: the spike should expose the natural complexity of each implementation rather than biasing one track toward the architecture of the other.

Both tracks should target:

```text
Same Tyk commit/version
Same CRS release
Inbound requests
Paranoia Level 1
Equivalent blocking threshold
Same benchmark hardware/environment
Same functional test suite
```

The exact CRS version must be pinned before work begins.

---

# Common functional target

Both tracks should initially target inbound application-layer protection at CRS Paranoia Level 1.

Priority attack families:

```text
930 - Local File Inclusion
931 - Remote File Inclusion
932 - Remote Code Execution
933 - PHP attacks
934 - Generic attacks
941 - Cross Site Scripting
942 - SQL Injection
943 - Session Fixation
944 - Java attacks
```

Compatible 920-series protocol/enforcement rules should be included where the Tyk request layer exposes sufficient information.

Initial body support should include:

```text
query parameters
cookies
application/x-www-form-urlencoded
application/json
```

Multipart and XML should be measured and documented but need not block the initial comparison.

---

# Track A — Native Coraza integration

## Objective

Produce the smallest credible native Coraza integration into Tyk capable of executing the target CRS profile.

The implementation should use Coraza directly from Go rather than attempting to expose Coraza through Goja.

---

## Proposed architecture

```text
HTTP request
    │
    ▼
Tyk HTTP pipeline
    │
    ▼
Coraza transaction
    │
    ├── request headers / URI
    ├── request body
    ├── CRS evaluation
    └── anomaly scoring
    │
    ├── allow
    └── block
```

Coraza should be integrated at the most natural point in Tyk's middleware/request lifecycle.

The spike should avoid unnecessary wrappers or abstraction layers unless they are needed for a fair production-oriented design.

---

## Track A deliverables

The Coraza agent should produce:

1. A Tyk branch implementing native Coraza support.

2. A pinned CRS configuration.

3. Request inspection and blocking for the common functional target.

4. Configuration for:

   * CRS enable/disable;
   * paranoia level;
   * inbound anomaly threshold;
   * ruleset location or embedding strategy.

5. Test results using the shared functional and CRS test corpus.

6. Performance measurements using the shared benchmark suite.

7. A dependency impact report.

8. A maintainability assessment.

9. A productionisation estimate.

---

## Track A questions

The Coraza spike should answer:

* How many lines of Tyk code are required?
* How invasive are the changes to the request pipeline?
* Does Coraza require request/response buffering changes?
* How are CRS files distributed?
* Would CRS updates require a new Tyk release?
* Would Coraza version updates require a new Tyk release?
* What new Go dependencies and transitive dependencies are introduced?
* What binary-size impact is introduced?
* What memory overhead exists per request?
* How does Coraza behave under high concurrency?
* How easy is rule exclusion/tuning?
* How much custom glue is required for Tyk-specific behaviour?
* What parts of the integration are likely to require ongoing maintenance?

---

# Track B — JavaScript CRS-derived WAF

## Objective

Determine whether a useful CRS-derived WAF can run in Tyk's existing Goja runtime while keeping the WAF implementation and rules independently distributable.

A small one-time extension to the Goja/security plugin ABI is allowed.

The Go side should not implement CRS semantics.

---

## Proposed architecture

### Build time

```text
OWASP CRS
    │
    ▼
SecLang parser / CRSLang tooling
    │
    ▼
normalized rule IR
    │
    ├── compatibility analysis
    │
    ▼
JS code generation
    │
    ▼
generated-rules.js
```

### Runtime

```text
HTTP request
    │
    ▼
Tyk request inspection hook
    │
    ├── curated request metadata
    ├── exact body representation
    ├── RE2 primitive
    └── request-scoped state
    │
    ▼
Goja
    │
    ▼
JS WAF runtime
    │
    ├── CRS variables
    ├── transforms
    ├── body parsing
    ├── generated rules
    ├── anomaly scoring
    └── blocking
```

---

# Proposed Track B Goja changes

## Request inspection hook

Introduce a dedicated early inspection hook rather than expanding every existing JS middleware object.

Example:

```js
function inspect(request, context) {
    const result = waf.inspect(request);

    if (result.blocked) {
        return {
            action: "block",
            status: 403
        };
    }

    return {
        action: "continue"
    };
}
```

The spike does not require arbitrary request rewriting from this hook.

---

## Curated request snapshot

Do not expose `*http.Request` directly.

Expose explicit fields needed for security inspection, for example:

```js
{
    method: "POST",
    requestURI: "/search?q=test",
    scheme: "https",
    protocol: "HTTP/1.1",

    host: "api.example.com",

    peer: {
        address: "10.0.0.5",
        port: 50123
    },

    clientIP: "203.0.113.10",

    contentLength: 1234,
    transferEncoding: [],

    headers: {},

    body: {
        base64: "..."
    }
}
```

---

## Exact body representation

Retain the current binary-safe base64 representation of request bodies and expose it to the inspection hook before convenience decoding.

Do not pass arbitrary request bytes through a Go/JavaScript string as the authoritative representation.

The spike must verify byte-for-byte round-trip correctness.

---

## Native RE2 primitive

Expose Go's `regexp` implementation through a generic security API.

Example:

```js
TykSecurity.regex.test(pattern, value)
TykSecurity.regex.exec(pattern, value)
```

Requirements:

* RE2-compatible matching;
* capture groups;
* explicit compile errors;
* bounded pattern size;
* bounded cache;
* no CRS-specific logic in Go.

---

## Request-scoped JavaScript state

Implement a general request-lifetime state facility:

```js
context.state.set("waf", {
    inboundScore: 5,
    matchedRules: [942100]
});
```

A later hook may retrieve it:

```js
const value = context.state.get("waf");
```

State should be serialized between Goja runtimes rather than preserving runtime object references.

It should be request-scoped, size-limited and namespaced.

This capability should be assessed independently as a potentially useful general Goja feature.

---

# Track B JavaScript runtime

The JS implementation should support enough CRS semantics for the common target.

Expected areas include:

```text
ARGS / ARGS_NAMES
request headers
cookies
URI / filename
TX variables
transformation pipelines
operators
chains
captures
setvar
tags
severity
anomaly scoring
PL1 gating
blocking evaluation
```

Initial body processors:

```text
query string
application/x-www-form-urlencoded
application/json
```

---

# Track B CRS compiler

The Goja runtime should not parse SecLang.

CRS should be converted at build time:

```text
CRS .conf
    │
    ▼
structured parser
    │
    ▼
normalized IR
    │
    ▼
compatibility analysis
    │
    ▼
generated JavaScript
```

Unsupported features must be reported explicitly.

No rule may be silently omitted.

---

# Libinjection

Track A will inherit Coraza's implementation of operators such as:

```text
@detectSQLi
@detectXSS
```

Track B may initially mark these as unsupported.

This difference should be explicitly measured rather than hidden.

Track B should report:

* which targeted rules use libinjection;
* which FTW tests fail because it is unavailable;
* estimated effort to port a compatible implementation to JS.

This is expected to be one of the most significant functional differences between the two tracks.

---

# Common test framework

Both implementations must run against the same tests.

## Functional tests

Create a common collection covering:

```text
benign requests
SQL injection
XSS
LFI
RFI
RCE
PHP attacks
Java attacks
session fixation
malformed encodings
JSON attacks
URL-encoded attacks
large inputs
```

The exact same HTTP requests should be sent to both implementations.

Expected output should include:

```text
allow/block
HTTP status
anomaly score where available
matched rule IDs
```

---

# CRS/go-ftw compatibility

Use CRS's test corpus where practical.

Each test should be classified for each track as:

```text
pass
unexpected failure
unsupported feature
host-unavailable
not applicable
```

The comparison must distinguish between:

> rules loaded

and:

> tests passed

The primary compatibility metric should be the percentage of applicable CRS tests passed.

Where practical, stock Coraza outside Tyk may also be used as a reference baseline to ensure the native Tyk integration itself is not altering expected Coraza behaviour.

---

# Performance benchmark

Run both implementations against the same Gateway configuration and hardware.

Measure at minimum:

```text
Gateway baseline: no WAF

Track A:
    Tyk + Coraza

Track B:
    Tyk + Goja JS WAF
```

Test request types:

```text
GET with small query
GET with many query parameters
small JSON POST
medium JSON POST
maximum inspected body
benign request
request matching one rule
request matching many rules
```

Measure:

```text
requests/sec
p50 latency
p95 latency
p99 latency
CPU utilisation
memory utilisation
allocations/request where practical
GC impact
```

Run sufficient concurrency levels to expose scaling behaviour, for example:

```text
1
10
50
100
500
```

or values appropriate to the existing Tyk performance environment.

---

# Startup and steady-state performance

Measure startup separately from request performance.

For Track A:

* Coraza engine creation;
* CRS parse/load time;
* compiled rule memory.

For Track B:

* JS program compilation;
* generated rule loading;
* Goja runtime setup;
* RE2 compilation/cache warm-up.

Steady-state benchmarks should be run after caches are warm.

Cold-start numbers should also be recorded separately.

---

# Code-size comparison

Record code changes using consistent tooling.

At minimum capture:

```text
Tyk Go LOC added
Tyk Go LOC modified
JS LOC added
compiler/tooling LOC
tests LOC
configuration LOC
generated LOC
```

Generated CRS JavaScript should be reported separately from human-maintained code.

For example:

| Metric                        | Coraza | JS |
| ----------------------------- | -----: | -: |
| Human-maintained Go LOC       |        |    |
| Human-maintained JS LOC       |        |    |
| Compiler LOC                  |    N/A |    |
| Test LOC                      |        |    |
| Generated LOC                 |    N/A |    |
| Files changed in Tyk          |        |    |
| External runtime dependencies |        |    |

Raw LOC should not determine the decision by itself, but it is an important indicator of ownership surface.

---

# Dependency comparison

## Track A

Record:

```text
new direct Go dependencies
new transitive dependencies
binary-size change
licensing considerations
security-update ownership
dependency update frequency
```

Include Coraza and any ruleset packaging dependency.

---

## Track B

Record:

```text
new Go dependencies
new JS dependencies
build-time compiler dependencies
generated artifact size
runtime JS artifact size
```

Build-only tooling should be distinguished from dependencies shipped in the Gateway.

---

# Maintainability assessment

Each agent should independently score their implementation from 1–5 across the following dimensions and provide supporting reasoning.

| Dimension                     | Coraza | JS |
| ----------------------------- | -----: | -: |
| Tyk integration simplicity    |        |    |
| CRS upgrade simplicity        |        |    |
| WAF engine upgrade simplicity |        |    |
| Rule fidelity                 |        |    |
| Testability                   |        |    |
| Debuggability                 |        |    |
| Operational simplicity        |        |    |
| Release independence          |        |    |
| Performance predictability    |        |    |
| Security review surface       |        |    |
| Long-term ownership burden    |        |    |

A second reviewer should then challenge both assessments.

---

# Upgrade experiment

The spike should include one artificial upgrade exercise.

After both implementations work against the initially pinned CRS version:

1. select a second CRS version;
2. upgrade each implementation;
3. measure:

   * code changes required;
   * generated changes;
   * tests requiring modification;
   * whether Tyk must be rebuilt;
   * elapsed engineering effort.

This is important because release independence is one of the main hypothesised advantages of Track B.

For Track A, distinguish between:

```text
rules-only CRS update
Coraza engine update
```

These may have different release implications.

---

# Configuration and tuning comparison

Both tracks should demonstrate at least:

```text
enable/disable WAF
set inbound anomaly threshold
set paranoia level
disable one rule by ID
exclude one request path
```

Compare how these features are represented and maintained.

Questions include:

* Can existing CRS exclusion syntax be reused?
* Does Tyk need its own configuration model?
* Can configuration be changed without rebuilding?
* Can exclusions be applied without recompiling generated JS?
* How much WAF-specific API surface becomes part of Tyk?

---

# Observability comparison

Both implementations should emit enough information to debug a blocked request.

Minimum desired event:

```json
{
    "blocked": true,
    "score": 10,
    "rules": [941100, 942100],
    "path": "/example"
}
```

Compare:

* ease of obtaining matched rule IDs;
* messages/tags;
* timing information;
* anomaly score;
* structured logging;
* ability to add metrics.

The spike should note whether instrumentation materially affects performance.

---

# Security review

Both tracks should identify their distinct security surfaces.

## Track A

Review:

```text
native dependency security
Coraza configuration
request-body handling
memory/resource limits
rule loading
update process
```

## Track B

Review:

```text
Goja resource exhaustion
body parsing
RE2 bridge
Go ↔ JS boundaries
generated rule correctness
request snapshot exposure
request-scoped state
JS dependency supply chain
```

Both should document fail-open/fail-closed behaviour on internal errors.

---

# Isolation and failure behaviour

Explicitly test what happens if the WAF fails.

Examples:

```text
invalid rule
regex compile failure
JS exception
Goja timeout
panic
out-of-memory-like large input
body parse error
unsupported content type
```

For each implementation document:

```text
request outcome
Gateway stability
log output
whether subsequent requests are affected
```

One WAF request must not poison shared state for later requests.

---

# A/B decision matrix

The final spike report should compare the two tracks using evidence rather than architectural preference.

Suggested weighting:

| Category                              | Weight |
| ------------------------------------- | -----: |
| CRS compatibility / security fidelity |    25% |
| Request performance                   |    20% |
| Maintainability                       |    15% |
| Upgrade/release independence          |    15% |
| Implementation complexity             |    10% |
| Operational complexity                |     5% |
| Security review surface               |     5% |
| Extensibility                         |     5% |

Weights may be adjusted before implementation begins but should not be changed after results are known without documenting why.

---

# Important architectural distinction

The comparison should not reduce to:

> Coraza is fewer lines of code.

That is likely to be true.

The relevant comparison is closer to:

```text
                     Coraza        JavaScript

Implementation       lower         higher

CRS fidelity         higher        initially lower

Runtime cost         likely lower  likely higher

Tyk dependency       higher        low

Gateway rebuild
for engine changes   yes           no

Independent WAF
release cadence       limited       strong

CRS upgrade effort    low           compiler-dependent

Security code owned
by Tyk team           low           higher
```

The spike exists to quantify these assumptions.

---

# Track A success criteria

Track A is successful if:

* Coraza executes the agreed CRS profile inside Tyk;
* requests can be blocked correctly;
* applicable CRS tests largely behave as expected;
* integration complexity is understood;
* performance is measured;
* binary/dependency impact is measured;
* upgrade/release implications are demonstrated.

---

# Track B success criteria

Track B is successful if:

* the WAF remains independently distributable JavaScript;
* no WAF engine is linked into Tyk;
* a meaningful subset of CRS PL1 executes;
* request bodies can be inspected byte-safely;
* native RE2 matching works;
* anomaly scoring and blocking work;
* unsupported CRS features are automatically reported;
* applicable CRS test pass rate is measured;
* performance is sufficient to justify comparison with the native implementation.

---

# Final deliverables

The spike should produce:

1. **Track A branch:** native Coraza integration.

2. **Track B branch:** Goja/security-hook changes plus JS WAF.

3. **Common benchmark repository/scripts.**

4. **Common functional test corpus.**

5. **CRS/go-ftw compatibility results for both.**

6. **Performance comparison.**

7. **Code-size comparison**, separating generated from maintained code.

8. **Dependency and binary-size comparison.**

9. **CRS upgrade experiment.**

10. **Maintainability assessment.**

11. **Security review notes.**

12. **Productionisation estimate for each approach.**

13. **A final recommendation backed by the measured results.**

---

# Questions the final review must answer

At completion we should be able to answer:

1. How much Tyk code does each implementation require?

2. How much total human-maintained code does each approach introduce?

3. What percentage of applicable CRS PL1 tests does each pass?

4. What functionality does Track B lose compared with Coraza?

5. How much of that gap is attributable specifically to libinjection, multipart, XML or unavailable HTTP-layer information?

6. What is the throughput and p99 cost of each implementation?

7. What is the memory/GC impact of each?

8. How much binary/dependency impact does Coraza introduce?

9. How difficult is upgrading CRS in each implementation?

10. Which upgrades require releasing a new Gateway binary?

11. How much security-sensitive code would Tyk own in each design?

12. Which design is easier to debug and tune in production?

13. Does the JS design's independent release model materially outweigh its added complexity?

14. Can the JS security-hook enhancements provide useful value beyond this WAF project?

15. Which approach should be productionised, and why?

---

# Expected outcome

The expected outcome is a concrete A/B comparison rather than an architectural proof-of-concept.

It is entirely acceptable for the spike to conclude that native Coraza is sufficiently simpler, faster and more complete that its compile-time dependency is worth accepting.

It is equally acceptable for the spike to conclude that the JavaScript implementation has enough CRS coverage and acceptable performance, and that independent WAF/ruleset releases provide sufficient product value to justify owning more of the runtime.

The decision should be based on measured compatibility, performance, code ownership, release characteristics and maintainability rather than on the initial preference for either implementation.
