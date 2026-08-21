# WAF A/B — Shared Corpus Format

Status: accepted with amendments on 2026-08-21. Scope: both Tracks.

## 1. Canonical location and amendment rule

The canonical corpus location is `docs/dev/program/waf-corpus/`. The example
fixture is `docs/dev/program/waf-corpus/example-corpus.json`. The location
moves only by amendment to `docs/dev/program/WAF-AB.contract.md`. No Track may
copy, fork, or relocate the fixture. Tests resolve it from the repository at
runtime; they do not use `go:embed` for this external package path.

## 2. Fixture container and versioning

A fixture file is a JSON array of case objects. Every case carries
`schema_version`. The current schema version is `1`. A runner that sees an
unknown `schema_version` fails loudly instead of guessing.

## 3. Case fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Format version; currently `1`. |
| `id` | string | Stable case identifier, `corpus-*`. Never renamed after acceptance. |
| `attack_family` | string | `920`, `930`, `931`, `932`, `933`, `934`, `941`, `942`, `943`, `944`, or `none` for special and benign traffic cases. |
| `applicable` | boolean | When `false` the runner records the case as `not_applicable`; it is skipped, not failed. |
| `provenance` | object | Origin record; see Section 8. |
| `required_features` | array of strings | Track-neutral capability names the case depends on; see Section 5. |
| `request` | object | The request to replay; see Section 4. |
| `expectations` | object | Mode-keyed expected outcomes; see Section 6. |
| `failure_policy` | object | Optional, failure-policy cases only: `fail_open` and `fail_closed` legs, same shape as a mode expectation. |

Unknown case fields are rejected by the fixture validator. Neither Track may
add Track-specific fields; the accepted bytes are identical for both.

## 4. Request mapping to the test framework

The `request` object maps onto the observed `test.TestCase` fields at
`test/http.go:19-51`:

| Corpus field | `test.TestCase` field | Notes |
| --- | --- | --- |
| `host` | `Host` | Host header override. |
| `method` | `Method` | Default `GET`. |
| `path` | `Path` | Path and, when convenient, in-URL query. |
| `proto` | `Proto` | `HTTP/1.1` or `HTTP/2.0`. |
| `headers` | `Headers map[string]string` | Single-valued headers. |
| `headers_array` | `HeadersArray map[string][]string` | Multi-value headers, e.g. repeated `Accept`. |
| `query_params` | `QueryParams` | Appended to the path by the runner. |
| `cookies` | `Cookies []*http.Cookie` | `{name, value}` objects. |
| `body_base64` | `Data interface{}` | See below. |
| `body_repeat` | — (runner-level) | Repeat factor applied to the decoded body before it fills `Data`. |

Body handling: `Data` is an `interface{}` value that the runner fills from the
decoded body. Corpus bodies are carried `base64`-encoded in `body_base64` so
exact bytes, malformed encodings, and binary payloads survive into both Tracks
byte-for-byte. An empty string means no body. `body_repeat` repeats the decoded
body N times (default 1) to build oversize payloads without huge fixtures.
Shared conformance tests prove that both runners generate identical bytes from
`body_repeat` and interpret `failure_policy` identically.

Framework-only fields (`BaseURL`, `Domain`, `PathParams`, `FormParams`,
`Delay`, function fields) are not part of the corpus; the runner derives them
from the Gateway under test. Assertion fields `Code` and `BodyMatch` are
expressed as expectations (Section 6), not as request data.

Header ordering: `Headers` and `HeadersArray` arrive as Go maps, so ordering
across distinct header names is not preserved by the framework. Header
ordering is therefore excluded from expectations. Multi-value order within one
header name is preserved via `HeadersArray`.

## 5. Required features registry (track-neutral)

A case declares every capability it depends on:

- `request_body_inspection` — request body is parsed and inspected.
- `body_restoration` — the original body is restored and delivered upstream
  after inspection.
- `request_body_limit` — oversize bodies are handled by a configured limit.
- `request_body_decompression` — `Content-Encoding` bodies are decompressed
  for inspection.
- `h2c_upgrade` — cleartext HTTP/2 upgrade handling.
- `http2_tls` — HTTP/2 over TLS.
- `rule_exclusions` — configured rule exclusions suppress matches.
- `inspection_failure_policy` — inspection errors follow a configured
  fail-open/fail-closed policy.

The vocabulary is track-neutral. Adding a name requires a format amendment;
Tracks must not interpret names Track-specifically.

## 6. Mode-keyed expectations

`expectations` is keyed by mode: `block` (blocking enforcement) and `audit`
(detection only). Each mode object:

| Field | Type | Meaning |
| --- | --- | --- |
| `verdict` | `"block"` \| `"allow"` | The engine decision. |
| `enforced` | boolean | Whether the decision was enforced on the wire. |
| `status` | integer | Expected HTTP response status. |
| `upstream_reached` | boolean | Whether the request reached upstream. |
| `anomaly_score` | object, optional | `{ "min": n, "max": n }` inbound score bounds, when available. |
| `matched_rule_ids` | object, optional | `{ "required": [...], "forbidden": [...] }` rule IDs that must or must not have matched, when available. |
| `log_record` | boolean | Audit mode: whether a decision log record is required. |
| `body_match` | string, optional | Regex the response body must contain (e.g. upstream echo proving body restoration). |

Failure-policy cases carry `failure_policy` with `fail_open` and `fail_closed`
legs of the same shape, one of which matches the configured policy.

### Audit-mode assertion rule

In audit mode the request must reach upstream, the response status must be
unchanged from the no-WAF behavior, no block may be enforced, and, when
`log_record` is true, the required log record must exist with the decision,
matched rule IDs, and anomaly score.

## 7. Result classification and reporting

Every executed case gets exactly one classification:

- `pass` — applicable test whose actual outcome matched expectations.
- `unexpected_failure` — applicable test that mismatched expectations or hit a
  harness error.
- `unsupported_feature` — the case requires a feature the Track does not claim
  (see Section 9).
- `host_unavailable` — the Gateway or upstream was unreachable or timed out.
- `not_applicable` — the case's `applicable` flag is false or the mode is not
  enabled; skipped, never counted as a failure.

Reporting output per Track and per run:

1. Applicable tests passed — count and rate over applicable executed tests
   (`pass` / (`pass` + `unexpected_failure`)). Reported separately from rules
   loaded.
2. Rules loaded — count (and digest) of CRS rules active in the configuration.
3. Unsupported features — the deduplicated list recorded during the run.
4. Classification counts — one count per enum value above.
5. Per-family breakdown — pass and unexpected_failure per attack family
   (`920`…`944`, `none`).

## 8. CRS regression-test provenance

Seeded cases record their CRS regression origin:

| Field | Meaning |
| --- | --- |
| `kind` | `crs_regression_seed` or `authored`. |
| `source_release` | e.g. `OWASP CRS v4.25.1 LTS`. |
| `source_tag` | e.g. `v4.25.1`. |
| `source_file` | Regression file under `tests/regression/tests/` in the coreruleset repository. |
| `original_test_name` | Original regression test title. |
| `license` | `Apache-2.0` for CRS-derived material. |
| `adaptation_notes` | What changed when seeding: encoding, target rule set (PL1, inbound threshold 5), assertion mapping. |

Authored cases (benign, oversize, h2c, TLS h2, failure policy, and similar)
use `kind: "authored"` with `null` CRS fields and notes explaining intent.

## 9. Unsupported Feature handling

Per CONTEXT.md, an Unsupported Feature is a required behavior a Track
identifies and does not claim to implement; it is not an unexpected failure.
When a case declares a `required_features` entry the Track does not claim, the
runner classifies the case `unsupported_feature`, records the feature in that
Track's dependency and compatibility evidence, and never silently omits it.

## 10. Shared consumption and the Seam

Both Tracks consume the identical accepted fixture bytes at the same Seam: the
shared request-inspection entry point `TestWAFSharedCorpus`. Neither Track may
add Track-specific fields, transform the bytes before the Seam, or maintain a
private variant. The example fixture is format-defining; the accepted corpus
is validated in a calibration pass against the pinned CRS baseline before both
Tracks consume it.

## 11. Example fixture

`docs/dev/program/waf-corpus/example-corpus.json` contains one case per attack
family (`920`, `930`, `931`, `932`, `933`, `934`, `941`, `942`, `943`, `944`)
plus one benign-traffic, one oversize-body, one h2c, one TLS h2, one
malformed-encoding, one exclusion, one body-restoration, and one
failure-policy case. It is valid JSON and exercises every field defined above,
including `headers_array`, `body_base64`, `body_repeat`, `cookies`,
`failure_policy`, and forbidden rule IDs.
