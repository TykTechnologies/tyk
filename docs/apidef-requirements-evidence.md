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
<!-- documents SW-REQ-057 -->
<!-- documents SW-REQ-058 -->
<!-- documents SW-REQ-059 -->
<!-- documents SW-REQ-060 -->
<!-- documents SW-REQ-061 -->
<!-- documents SW-REQ-062 -->
<!-- documents SW-REQ-063 -->
<!-- documents SW-REQ-065 -->
<!-- documents SW-REQ-068 -->
<!-- documents SW-REQ-069 -->
<!-- documents SW-REQ-070 -->
<!-- documents SW-REQ-071 -->
<!-- documents SW-REQ-072 -->
<!-- documents SW-REQ-073 -->
<!-- documents SW-REQ-074 -->

This document records the first API-definition support-model proof slice. The
slice is deliberately limited to small API-definition helper models and does
not claim API import, full OAS conversion, route generation, gateway request
admission, or the full API definition lifecycle.

`SYS-REQ-104` covers API-definition support model helpers that preserve typed
health-check wire values, host-list access behavior, and error-override helper
state, embedded Classic API definition schema data, OAS path/server helper
shapes, OAS root extension helper shapes, OAS server model helper shapes, OAS URL rewrite helper shapes, OAS schema visitor/unicode-escape helper behavior, OAS schema example
extraction shapes, OAS schema-validation helper behavior, OAS internal endpoint
helper shapes, OAS endpoint tracking helper shapes, OAS utility helper shapes,
OAS deprecated-wrapper conversion shapes, OAS Tyk streaming extension shape, OAS event-handler helper shapes,
OAS server-regeneration helper shapes,
internal reflection support helper behavior,
custom middleware definition enablement classification, OAS extension header
name/value helper shapes, OAS extension error-override helper shapes, adapter
interface and GraphQL utility helper behavior, GraphQL config adapter
selection behavior, AsyncAPI adapter support-shape generation, and OpenAPI
adapter support-shape generation, and GraphQL engine adapter utility behavior
and proxy-only and supergraph engine adapter configuration behavior without
silent data-shape drift.

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

`SW-REQ-057` owns the concrete `apidef/oas` Tyk streaming extension data shape.
Its evidence covers the stable `streams` JSON field name, explicit nil and
empty stream map representation without field omission, populated nested stream
configuration preservation, and deterministic JSON round-trip decoding. This
evidence does not claim extension attachment or removal lifecycle behavior,
streaming engine execution, stream configuration validation, API import, route
generation, request matching, gateway request admission, middleware execution,
or final client-visible runtime behavior.

`SW-REQ-058` owns the concrete `apidef/oas` event-handler data-shape and
Classic metadata conversion helpers. Its evidence covers stable event kind
aliases, webhook, JavaScript VM, and log-specific JSON merge/decode behavior,
malformed JSON rejection without receiver mutation, direct Classic configuration
extraction for supported handler types, Classic Fill behavior for webhook,
JavaScript VM, and log metadata, unsupported handler skipping, clearing OAS
handlers when Classic input or OAS input is empty, ExtractTo replacement of
supported existing Classic handlers while preserving unsupported existing handlers, and
deterministic repeated conversion behavior. This evidence does not claim event
triggering, webhook delivery, JavaScript execution, log emission, middleware
execution, API import, route generation, request matching, gateway request
admission, external handler plugin behavior, or final client-visible runtime
behavior.

`SW-REQ-059` owns the concrete `apidef/oas` server-regeneration helpers used by
API-definition support models. Its evidence covers Tyk-managed absolute and
relative server URL generation from custom domains, default gateway hosts, edge
endpoints, API tags, hybrid mode, listen paths, and base or child versioning
configuration; URL-path, query-parameter, and header-versioned URL shapes;
fallback-to-default and external-child direct-access behavior; replacement of
previously generated Tyk servers while preserving user-provided servers;
normalized URL deduplication; extraction of user-provided servers from mixed
server lists; generated invalid server-template errors; and deterministic
repeated generation. This evidence does not claim API import, full OAS
conversion, route generation, request matching, gateway request admission,
gateway listener binding, edge gateway availability, middleware execution, or
final client-visible routing behavior.

`SW-REQ-060` owns the concrete `apidef/oas` validator helpers used by
API-definition support models. Its evidence covers OAS definitions-key
selection for embedded schema data, embedded OAS schema loading with the Tyk
extension schema injected under supported OAS versions, deterministic default
schema-version selection, major/minor/patch version resolution, OAS object and
template validation, template allowance for intentionally omitted Tyk extension
required fields, aggregated validation errors for malformed documents, and
explicit unsupported or malformed schema-version errors. This evidence does not
claim correctness of the upstream gojsonschema library, completeness of
embedded OpenAPI schemas, API import, route generation, request matching,
gateway request admission, persistence, middleware execution, or final
client-visible validation responses.

`SW-REQ-061` owns the concrete `apidef/oas` root extension data shape and
Classic metadata conversion helpers. Its evidence covers top-level
`x-tyk-api-gateway` info, upstream, server, middleware, state, versioning, and
error-override mapping to and from Classic API definitions; deterministic
version name-to-ID sorting; Classic unversioned `VersionData` default
initialization during extraction; omission and temporary nil restoration for
empty optional middleware and versioning shapes; explicit Classic
error-override disablement when the OAS root has no error-override shape;
present disabled error-override preservation; and import-time context-variable
and traffic-log defaulting only when the corresponding global middleware helper
is absent. This evidence does not claim full API import, full OAS conversion,
route generation, request matching, gateway request admission, middleware
execution, error response selection, context-variable runtime behavior,
traffic-log emission, or final client-visible routing behavior.

`SW-REQ-062` owns the concrete `apidef/oas` server data shape and Classic
metadata conversion helpers. Its evidence covers protocol, port, listen path,
static client certificate, gateway tag, custom domain, detailed activity log,
detailed tracing, IP access-control, and batch-processing field mapping to and
from Classic API definitions; empty optional child omission during Fill;
default enabled inversion child preservation for tags, domains, and IP access
control; temporary nil-child initialization and receiver restoration during
ExtractTo; disabled/enabled inversion fields for tags, domains, and IP access
control; zero-value boundary mappings; and deterministic repeated conversion
behavior.
This evidence does not claim gateway listener binding, request routing,
authentication execution, mutual-TLS handshakes, event delivery, detailed
activity log emission, detailed tracing export, IP access-control enforcement,
batch request execution, full API import, full OAS conversion, route
generation, gateway request admission, middleware execution, or final
client-visible routing behavior.

`SW-REQ-063` owns the concrete `apidef/oas` URL rewrite data shape and Classic
metadata conversion helpers. Its evidence covers Classic URL rewrite metadata
Fill and ExtractTo behavior, header, query, path, session metadata, request
body, and request context trigger rule mapping, empty trigger and operation
rewrite omission, deterministic input-kind and name sorting, URL rewrite input
validation, invalid-value error reporting, and operation-level fill/extract
hooks. This evidence does not claim gateway route matching, regular-expression
execution, request URL rewriting at runtime, request-context extraction,
session metadata lookup, middleware execution, API import, full OAS conversion,
route generation, gateway request admission, upstream request dispatch, or
final client-visible routing behavior.

`SW-REQ-065` owns the concrete `internal/reflect` support helpers used by
API-definition support model flows. Its evidence covers Clone deep-copy wrapper
behavior, OAS empty value classification for zero structs, empty maps/slices,
nil/empty pointers and bool pointers, JSON-compatible Cast success and
unmarshalable input errors, Flatten for nested maps/slices/structs, nils,
strings, bools, numeric coalescing, unsupported value errors, non-string
map-key rejection, and deterministic repeated helper results. This evidence
does not claim arbitrary reflection correctness, upstream clone library
correctness beyond wrapper behavior under test, full OAS conversion, API
import, route generation, gateway request admission, middleware execution,
persistence, or client-visible runtime behavior.

`SW-REQ-068` owns the concrete `apidef/adapter` import interface and GraphQL
utility helpers used by API-definition adapter flows. Its evidence covers the
ImportAdapter API-definition/error result shape, enabled and disabled GraphQL
adapter classification for proxy-only, subgraph-as-proxy-only, supergraph,
universal data graph, and unknown modes; construction of new GraphQL API
definitions with active execution-engine defaults, initialized proxy auth
headers, generated API IDs, default version metadata, and strip-listen-path
behavior; and deterministic name sorting for field configurations and data
sources. This evidence does not claim AsyncAPI or OpenAPI import correctness,
GraphQL schema parsing, GraphQL engine configuration generation, gateway API
loading, route generation, request matching, gateway request admission,
middleware execution, upstream GraphQL execution, persistence, analytics, or
final client-visible runtime behavior.

`SW-REQ-069` owns the concrete `apidef/adapter` GraphQL config adapter used by
API-definition adapter flows. Its evidence covers V2 and V3 schema option
plumbing, HTTP and streaming client option plumbing, nonnil default clients,
zero-timeout streaming defaults, explicit unsupported-version and
unsupported-mode errors, V2 selection for proxy-only, subgraph-as-proxy-only,
supergraph, and universal data graph modes, V3 selection for supported
proxy-only and universal data graph modes, and local rejection of V3 supergraph
mode. This evidence does not claim correctness of downstream GraphQL engine
adapter packages, GraphQL schema parsing, GraphQL execution, AsyncAPI or
OpenAPI import correctness, gateway API loading, route generation, request
matching, gateway request admission, middleware execution, upstream
availability, persistence, analytics, or final client-visible runtime behavior.

`SW-REQ-070` owns the concrete `apidef/adapter` AsyncAPI adapter used by
API-definition adapter flows. Its evidence covers well-formed AsyncAPI import
into a new active GraphQL execution-engine API definition, Kafka broker and
binding conversion into GraphQL Kafka data-source configuration, AsyncAPI
argument template conversion, channel-specific server selection and default
server fallback, deterministic field/data-source sorting,
schema printing into the API definition, malformed input errors, unsupported
server protocol errors, missing server URL errors, and invalid Kafka
data-source configuration errors. This evidence does not claim complete
AsyncAPI specification coverage, correctness of the upstream AsyncAPI parser or
GraphQL translator, downstream GraphQL engine adapter correctness, GraphQL
execution, Kafka connectivity or consumption behavior, gateway API loading,
route generation, request matching, gateway request admission, middleware
execution, upstream availability, persistence, analytics, or final
client-visible runtime behavior.

`SW-REQ-071` owns the concrete `apidef/adapter` OpenAPI adapter used by
API-definition adapter flows. Its evidence covers well-formed OpenAPI import
into a new active GraphQL execution-engine API definition, REST data-source
generation for supported query and mutation methods, first-server URL joining,
path and query argument template conversion, operation-ID and endpoint/method
field-name derivation, JSON request-body argument template creation,
deterministic field/data-source sorting, schema printing into the API
definition, malformed input errors, nil and serverless document errors,
malformed server URL errors, and missing JSON request-body media or schema
errors. This evidence does not claim complete OpenAPI specification coverage,
correctness of the upstream OpenAPI parser or GraphQL translator, downstream
GraphQL engine adapter correctness, REST upstream availability, GraphQL
execution, gateway API loading, route generation, request matching, gateway
request admission, middleware execution, persistence, analytics, or final
client-visible runtime behavior.

`SW-REQ-072` owns the concrete `apidef/adapter/gqlengineadapter` utility
helpers used by GraphQL engine adapter configuration assembly. Its evidence
covers schema parse/normalize result propagation, subscription protocol and
type mapping, header conversion, canonical duplicate-header removal with
first-map precedence, GraphQL-operation-to-REST datasource conversion, missing
operation errors, internal Tyk URL conversion with internal API headers, SSE and
SSE POST configuration, ordered field-argument configuration, deterministic URL
query extraction with explicit API-definition query appending, invalid query
errors, GraphQL datasource factory construction with caller-supplied HTTP
clients, invalid subscription-client factory errors, and default subscription
client factory selection. This evidence does not claim correctness of
proxy-only, supergraph, or universal-data-graph adapter end-to-end
configuration generation; GraphQL schema semantic completeness beyond local
parse/normalize result propagation; REST or GraphQL upstream availability;
subscription transport execution; gateway API loading; route generation;
request matching; gateway request admission; middleware execution; persistence;
analytics; or final client-visible runtime behavior.

`SW-REQ-073` owns the concrete `apidef/adapter/gqlengineadapter` proxy-only
engine adapter configuration assembly. Its evidence covers local schema parsing
when no schema is supplied, caller-supplied schema reuse, proxy request header
conversion into static upstream headers, internal Tyk URL conversion with the
internal API header, proxy subscription settings including SSE POST mode,
caller-supplied HTTP and streaming clients in the datasource factory,
configured subscription-client factory use, schema-derived datasource and field
argument configuration, repeated-input determinism, and schema parse error
propagation. This evidence does not claim GraphQL schema semantic completeness
beyond local parse/normalize result propagation, correctness of the upstream
graphql-go-tools proxy config factory, subgraph or federation semantics beyond
proxy-only configuration shape, GraphQL execution, subscription transport
execution, REST or GraphQL upstream availability, gateway API loading, route
generation, request matching, gateway request admission, middleware execution,
persistence, analytics, or final client-visible runtime behavior.

`SW-REQ-074` owns the concrete `apidef/adapter/gqlengineadapter` supergraph
engine adapter configuration assembly. Its evidence covers conversion of
non-empty subgraph entries into federation-enabled GraphQL datasource
configuration, empty-SDL subgraph skipping, subgraph/global header merging with
subgraph precedence and canonical HTTP names, internal Tyk subgraph URL
conversion with the internal API header, subgraph subscription settings
including SSE POST mode, caller-supplied HTTP, streaming, and subscription
client inputs in the generated federation datasource factory, batch datasource
factory presence or absence based on the disable-query-batching flag, merged SDL
error propagation, empty-subgraph boundary behavior, and repeated-input
determinism. This evidence does not claim GraphQL federation semantic
correctness beyond local config assembly and upstream error propagation,
correctness of the upstream graphql-go-tools federation config factory, GraphQL
execution, subscription transport execution, REST or GraphQL upstream
availability, gateway API loading, route generation, request matching, gateway
request admission, middleware execution, persistence, analytics, or final
client-visible runtime behavior.
