# API Definition Requirements Evidence

<!-- documents SYS-REQ-104 -->
<!-- documents SW-REQ-019 -->
<!-- documents SW-REQ-020 -->
<!-- documents SW-REQ-021 -->
<!-- documents SW-REQ-033 -->
<!-- documents SW-REQ-042 -->
<!-- documents SW-REQ-044 -->
<!-- documents SW-REQ-045 -->
<!-- documents SW-REQ-047 -->
<!-- documents SW-REQ-051 -->
<!-- documents SW-REQ-052 -->
<!-- documents SW-REQ-053 -->
<!-- documents SW-REQ-054 -->
<!-- documents SW-REQ-055 -->
<!-- documents SW-REQ-056 -->

This document records the first API-definition support-model proof slice. The
slice is deliberately limited to small API-definition helper models and does
not claim API import, full OAS conversion, route generation, gateway request
admission, or the full API definition lifecycle.

`SYS-REQ-104` covers API-definition support model helpers that preserve typed
health-check wire values, host-list access behavior, and error-override helper
state, embedded Classic API definition schema data, OAS path/server helper
shapes, OAS schema visitor/unicode-escape helper behavior, OAS schema example
extraction shapes, OAS internal endpoint helper shapes, OAS endpoint tracking
helper shapes, OAS utility helper shapes, OAS deprecated-wrapper conversion
shapes, custom middleware definition
enablement classification, OAS extension header name/value helper shapes, and
OAS extension error-override helper shapes without silent
data-shape drift.

`SW-REQ-019` owns the concrete `apidef` health-check constants and JSON struct
shapes. Its evidence covers status and component-type constants, populated JSON
field names, nested detail entries, and omission of empty optional response
fields. It does not claim runtime health computation, RPC synchronization, or
gateway node health behavior.

`SW-REQ-020` owns the concrete `apidef.HostList` helper behavior. Its evidence
covers empty and pre-populated constructors, Set replacement, All and Len
observation, valid indexed access, and explicit negative or out-of-range index
errors. It does not claim upstream host selection, load balancing, service
discovery, or gateway routing behavior.

`SW-REQ-021` owns the concrete `apidef` error-override helper state and matcher
compilation behavior. Its evidence covers text/XML versus HTML template storage
and retrieval, inline-template availability reporting, successful message regex
compilation, preserving an already compiled matcher, no-op empty-pattern
compilation, and explicit invalid-regex errors. It does not claim gateway error
response selection, template execution, response-body matching, or API request
behavior.

`SW-REQ-033` owns the embedded Classic API definition schema document exposed as
`apidef.Schema`. Its evidence covers non-empty embedded content, JSON
parseability, and stable top-level schema metadata. It does not claim full API
definition validation behavior, schema completeness, API import, OAS conversion,
route generation, gateway request admission, or the full API definition
lifecycle.

`SW-REQ-042` owns the concrete `internal/oasutil` helper behavior for OAS path
ordering and server URL template parsing. Its evidence covers ordered path
extraction, Tyk path-priority sorting with parameterized paths, normalized
server URL generation, deterministic server-variable defaults, empty URL
handling, non-capturing regex patterns, malformed braces, empty or invalid
variable names, duplicate variable names, invalid regex patterns, and rejected
capturing groups. This evidence does not claim gateway route generation, API
import, request matching, full OAS conversion, or correctness of the upstream
OpenAPI library.

`SW-REQ-044` owns the concrete `pkg/schema` OAS visitor and unicode-escape
conversion helpers. Its evidence covers visitor initialization, manipulation
registration and insertion-order application, visited-state reset, one-time
schema visitation for components, operation parameters, request bodies,
response bodies, response headers, callbacks, properties, items, additional
properties, not/allOf/anyOf/oneOf branches, circular-reference stopping, nil
schema references, nil path items, JSON-schema unicode escape conversion to RE2
syntax, RE2 escape restoration in schema patterns and error strings, empty
pattern handling, non-matching pattern preservation, and already-converted input
preservation. This evidence does not claim full API-definition validation,
schema completeness, API import, OAS conversion, route generation, request
matching, gateway request admission, or correctness of the upstream OpenAPI
library.

`SW-REQ-045` owns the concrete `internal/middleware.Enabled` helper for
custom-middleware definition enablement classification. Its evidence covers
empty definition lists, disabled named definitions, unnamed definitions, mixed
lists with no enabled named definition, named enabled definitions, and mixed
lists where one enabled named definition makes the helper return enabled. This
evidence does not claim middleware chain construction, plugin loading,
middleware execution, response interruption status codes, gateway request
handling, or final client-visible middleware behavior.

`SW-REQ-047` owns the concrete `apidef/oas` header helper behavior used by OAS
extension shapes. Its evidence covers appending added headers in order, mapping
populated header lists, explicit empty maps for nil and empty lists,
last-value-wins duplicate header names, deterministic name-sorted conversion
from maps to header lists, and explicit empty header lists for nil and empty
maps. This evidence does not claim full OAS conversion, header transformation
middleware execution, API import, route generation, request matching, gateway
request admission, or final client-visible header behavior.

`SW-REQ-051` owns the concrete `apidef/oas` error-override shape mapping
helpers used by OAS extension models. Its evidence covers Classic disabled flag
to OAS enabled flag mapping, nil and empty override maps, status-code override
lists, optional matcher fields, response status/body/message/template/header
fields, nil-match overrides, nil receiver extraction, and deterministic repeated
Fill/ExtractTo round trips. This evidence does not claim gateway error response
selection, matcher evaluation, template rendering or execution, response-body
matching, middleware execution, API import, route generation, request matching,
gateway request admission, or final client-visible response behavior.

`SW-REQ-052` owns the concrete `apidef/oas` schema example extraction helper
used by API-definition support shapes. Its evidence covers nil schema
references, explicit example precedence, object property recursion, array item
example derivation, first-enum-value fallback, primitive defaults, unknown-type
nil fallback, and deterministic repeated extraction for valid schema references
with non-nil schema values. This evidence does not claim full OAS conversion,
schema validation, response selection, mock-response middleware execution, API
import, route generation, request matching, gateway request admission, non-nil
schema references with nil schema values, or final client-visible response
behavior.

`SW-REQ-053` owns the concrete `apidef/oas` internal endpoint shape mapping
helper used by API-definition extension models. Its evidence covers Classic
Disabled to OAS Enabled inversion, OAS Enabled to Classic Disabled inversion
while preserving endpoint path and method metadata, nil/no-op operation
extraction, enabled operation filling, disabled empty internal configuration
omission, and deterministic repeated Fill/ExtractTo behavior. This evidence
does not claim API import, route generation, request matching, gateway request
admission, internal-looping behavior, middleware execution, access-control
enforcement, or final client-visible routing behavior.

`SW-REQ-054` owns the concrete `apidef/oas` endpoint tracking shape mapping
helper used by API-definition extension models. Its evidence covers Classic
Disabled to OAS Enabled inversion for both trackEndpoint and doNotTrackEndpoint,
OAS Enabled to Classic Disabled inversion into the correct Classic extended-path
list while preserving endpoint path and method metadata, nil/no-op operation
extraction, enabled tracking operation filling, disabled empty tracking
configuration omission, and deterministic repeated Fill/ExtractTo behavior.
This evidence does not claim analytics collection, log emission, request
matching, gateway request admission, middleware execution, access-control
behavior, or final client-visible runtime behavior.

`SW-REQ-055` owns the concrete `apidef/oas` utility helpers used by
API-definition extension model conversion. Its evidence covers valid
map-shaped extension data conversion into target structs, non-map conversion
input rejection without target mutation, empty versus populated shape
classification through the OAS `ShouldOmit` compatibility alias, missing main
version initialization, preservation of non-main version entries, updating only
the main version entry requested by the caller, and deterministic repeated main
version observation. This evidence does not claim full OAS conversion, schema
validation, API import, route generation, request matching, gateway request
admission, middleware execution, error reporting for malformed map contents, or
final client-visible runtime behavior.

`SW-REQ-056` owns the concrete `apidef/oas` deprecated OldOAS conversion helper
used by API-definition support models. Its evidence covers conversion of a
valid deprecated wrapper into the newer OAS wrapper while preserving core
OpenAPI document fields, and unserializable deprecated wrapper data returning
an error with no converted OAS object. This evidence does not claim full API
import, full migration correctness, route generation, request matching,
gateway request admission, middleware execution, schema completeness,
exhaustive invalid-document validation, or final client-visible runtime
behavior.
