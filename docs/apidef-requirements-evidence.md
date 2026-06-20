# API Definition Requirements Evidence

<!-- documents SYS-REQ-104 -->
<!-- documents SW-REQ-019 SW-REQ-020 SW-REQ-021 SW-REQ-033 SW-REQ-042 SW-REQ-044 SW-REQ-045 SW-REQ-047 SW-REQ-051 SW-REQ-052 -->
<!-- documents SW-REQ-053 SW-REQ-054 SW-REQ-055 SW-REQ-056 SW-REQ-057 SW-REQ-058 SW-REQ-059 SW-REQ-060 SW-REQ-061 SW-REQ-062 -->
<!-- documents SW-REQ-063 SW-REQ-065 SW-REQ-068 SW-REQ-069 SW-REQ-070 SW-REQ-071 SW-REQ-072 SW-REQ-073 SW-REQ-074 SW-REQ-075 -->
<!-- documents SW-REQ-076 SW-REQ-077 SW-REQ-078 SW-REQ-079 SW-REQ-080 SW-REQ-081 SW-REQ-082 SW-REQ-083 SW-REQ-084 SW-REQ-085 -->
<!-- documents SW-REQ-086 SW-REQ-087 SW-REQ-088 SW-REQ-089 SW-REQ-090 SW-REQ-091 SW-REQ-092 SW-REQ-093 SW-REQ-094 -->
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
<!-- documents SW-REQ-075 -->
<!-- documents SW-REQ-076 -->
<!-- documents SW-REQ-077 -->
<!-- documents SW-REQ-078 -->
<!-- documents SW-REQ-079 -->
<!-- documents SW-REQ-080 -->
<!-- documents SW-REQ-081 -->
<!-- documents SW-REQ-082 -->
<!-- documents SW-REQ-083 -->
<!-- documents SW-REQ-084 -->
<!-- documents SW-REQ-085 -->
<!-- documents SW-REQ-086 -->
<!-- documents SW-REQ-087 -->

This document records the first API-definition support-model proof slice. The
slice is deliberately limited to small API-definition helper models and does
not claim API import, full OAS conversion, route generation, gateway request
admission, or the full API definition lifecycle.

`SYS-REQ-104` covers API-definition support model helpers that preserve typed
health-check wire values, host-list access behavior, and error-override helper
state, embedded Classic API definition schema data, Classic API definition core
helper behavior, importer source dispatcher behavior, Apiary Blueprint importer
conversion behavior, Swagger importer conversion behavior, WSDL importer
conversion behavior, Classic API definition migration helper behavior,
notification helper behavior, OAS authentication helper shapes, OAS path/server
helper shapes, OAS default-extension helper shapes, OAS middleware helper
shapes, OAS root document helper behavior, OAS operation document helper
behavior, OAS security document helper behavior, OAS upstream document helper
behavior, Bento configuration schema-generation helper behavior, OAS root
extension helper shapes, OAS server model helper shapes, OAS URL rewrite
helper shapes, OAS schema visitor/unicode-escape helper behavior, OAS schema
example extraction shapes, OAS schema-validation helper behavior, OAS internal
endpoint helper shapes, OAS endpoint tracking helper shapes, OAS utility helper
shapes, OAS deprecated-wrapper conversion shapes, OAS Tyk streaming extension
shape, OAS event-handler helper shapes, OAS server-regeneration helper shapes,
internal reflection support helper behavior,
custom middleware definition enablement classification, OAS extension header
name/value helper shapes, OAS extension error-override helper shapes, adapter
interface and GraphQL utility helper behavior, GraphQL config adapter
selection behavior, AsyncAPI adapter support-shape generation, and OpenAPI
adapter support-shape generation, and GraphQL engine adapter utility behavior
and proxy-only, supergraph, and universal-data-graph engine adapter
configuration behavior, plus engine v3 proxy-only adapter configuration
and supergraph adapter configuration behavior, and engine v3 utility behavior,
engine v3 universal-data-graph adapter configuration behavior, and Classic API
definition core model helper behavior, and Apiary Blueprint importer conversion
behavior, and importer source dispatcher behavior, without silent data-shape
drift, plus Swagger importer conversion behavior and WSDL importer conversion
behavior, plus Classic API definition migration helper behavior and
notification helper behavior, plus OAS authentication helper behavior.
It also includes OAS default-extension, middleware, root document, operation
document, security document, upstream document, and Bento configuration
schema-generation helper behavior.

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

`SW-REQ-075` owns the concrete `apidef/adapter/gqlengineadapter`
universal-data-graph engine adapter configuration assembly. Its evidence covers
schema parsing when no schema is supplied, caller-supplied schema reuse,
preservation of explicit field path and default-mapping settings,
schema-derived field argument configuration, REST datasource configuration with
URL query extraction and explicit query variables, GraphQL datasource
configuration with caller-supplied HTTP, streaming, and subscription-client
factory inputs, GraphQL-operation-as-REST configuration, Kafka subscription
datasource configuration, schema-derived child-node metadata for non-REST
datasources, schema and datasource configuration error propagation, and
repeated-input determinism. This evidence does not claim GraphQL schema
semantic completeness beyond local parse/normalize result propagation,
correctness of upstream graphql-go-tools datasource factories, REST or GraphQL
upstream availability, Kafka broker availability or consumption behavior,
GraphQL execution, subscription transport execution, gateway API loading, route
generation, request matching, gateway request admission, middleware execution,
persistence, analytics, or final client-visible runtime behavior.

`SW-REQ-076` owns the concrete
`apidef/adapter/gqlengineadapter/enginev3` proxy-only engine adapter
configuration assembly. Its evidence covers local schema parsing when no schema
is supplied, caller-supplied schema reuse, proxy request header conversion into
static upstream headers, internal Tyk URL conversion with the internal API
header, proxy subscription type mapping, caller-supplied HTTP and streaming
clients in the datasource factory, configured subscription-client factory use,
schema-derived datasource and field argument configuration, repeated-input
determinism, default subscription-client factory selection, and schema parse
error propagation. This evidence does not claim GraphQL schema semantic
completeness beyond local parse/normalize result propagation, correctness of
the upstream graphql-go-tools/v2 proxy config factory, GraphQL execution,
subscription transport execution, REST or GraphQL upstream availability,
gateway API loading, route generation, request matching, gateway request
admission, middleware execution, persistence, analytics, or final
client-visible runtime behavior.

`SW-REQ-077` owns the concrete
`apidef/adapter/gqlengineadapter/enginev3` supergraph engine adapter
configuration assembly. Its evidence covers conversion of non-empty subgraph
entries into federation-enabled GraphQL datasource configuration, empty-SDL
subgraph skipping, subgraph/global header merging with subgraph precedence and
canonical HTTP names, internal Tyk subgraph URL conversion with the internal API
header, subgraph subscription type mapping, caller-supplied HTTP, streaming,
and subscription-client factory inputs in the generated federation datasource
factory, merged SDL error propagation, empty-subgraph boundary behavior, and
repeated-input determinism. This evidence does not claim GraphQL federation
semantic correctness beyond local config assembly and upstream error
propagation, correctness of the upstream graphql-go-tools/v2 federation config
factory, GraphQL execution, subscription transport execution, REST or GraphQL
upstream availability, gateway API loading, route generation, request matching,
gateway request admission, middleware execution, persistence, analytics, or
final client-visible runtime behavior.

`SW-REQ-078` owns the concrete
`apidef/adapter/gqlengineadapter/enginev3` utility helpers used by GraphQL
engine v3 adapter configuration assembly. Its evidence covers API-definition
header conversion, GraphQL-operation-to-REST datasource conversion, missing
operation errors, ordered field-argument configuration, deterministic URL query
extraction with explicit API-definition query appending, invalid query errors,
websocket subprotocol selection for subscription types, GraphQL datasource
factory construction with caller-supplied HTTP clients and subscription-client
factory inputs, and invalid subscription-client factory errors. This evidence
does not claim correctness of proxy-only, supergraph, or universal-data-graph
adapter end-to-end configuration generation; GraphQL schema semantic
completeness; REST or GraphQL upstream availability; subscription transport
execution; Kafka connectivity or consumption behavior; gateway API loading;
route generation; request matching; gateway request admission; middleware
execution; persistence; analytics; or final client-visible runtime behavior.

`SW-REQ-079` owns the concrete
`apidef/adapter/gqlengineadapter/enginev3` universal-data-graph engine adapter
configuration assembly. Its evidence covers schema parsing when no schema is
supplied, caller-supplied schema reuse, preservation of explicit field path and
default-mapping settings, schema-derived field argument configuration, REST
datasource configuration with URL query extraction and explicit query
variables, GraphQL datasource configuration with caller-supplied HTTP,
streaming, and subscription-client factory inputs, GraphQL-operation-as-REST
configuration, Kafka subscription datasource configuration, schema-derived
child-node metadata, schema and datasource configuration error propagation, and
repeated-input determinism. This evidence does not claim GraphQL schema
semantic completeness beyond local parse/normalize result propagation,
correctness of upstream graphql-go-tools/v2 datasource factories, REST or
GraphQL upstream availability, Kafka broker availability or consumption
behavior, GraphQL execution, subscription transport execution, gateway API
loading, route generation, request matching, gateway request admission,
middleware execution, persistence, analytics, or final client-visible runtime
behavior.

`SW-REQ-080` owns the concrete `apidef/api_definitions.go` Classic API
definition data model and helper behavior. Its evidence covers wire-shape
constants and struct preservation, route/header/rate-limit/version/discovery
helper classification, upstream-auth and auth-source classification,
scope-claim and scope-policy mapping selection, database compatibility
encoding and decoding for version names, upstream certificate maps, pinned key
maps, and validation schemas, legacy decode fallback behavior for unencoded
keys, regex matcher initialization and normal/reverse matching, deterministic
dummy API defaults, template JSON/XML marshaling helpers, JWK cache timeout
fallback, uptime command append behavior, and webhook/JSVM/log event-handler
scan conversion with explicit unmarshalable-input errors. This evidence does
not claim gateway API loading, API import or migration completeness, OAS
conversion completeness, route generation, request matching, gateway request
admission, middleware execution, upstream authentication execution, webhook
delivery, JavaScript execution, log emission, persistence backend correctness,
analytics, GraphQL execution, streaming execution, or final client-visible
runtime behavior.

`SW-REQ-087` owns the concrete `apidef/oas/authentication.go` OAS
authentication helper shapes. Its evidence covers security-processing mode
validation, protected-resource metadata validation and default well-known
paths, aggregate Authentication Fill/ExtractTo behavior, supported and
unsupported security-scheme import, base identity-provider precedence,
authentication source and signature mapping, scope mapping determinism, HMAC
and OIDC conversion, custom key lifetime and certificate auth conversion,
custom plugin authentication and authentication plugin conversion, and
ID-extractor configuration conversion. This evidence does not claim OpenAPI
security requirement evaluation, gateway authentication enforcement, token
validation, certificate validation, HMAC signature verification, OIDC provider
execution, custom plugin execution, ID extraction at runtime, full OAS
import/export correctness, gateway API loading, route generation, request
matching, gateway request admission, persistence, analytics, or final
client-visible runtime behavior.

`SW-REQ-088` owns the concrete `apidef/oas/default.go` default-extension
helpers. Its evidence covers import and non-import default x-tyk-api-gateway
shape construction, server-variable substitution, missing and unresolved
server-variable errors, invalid manual upstream and server URL errors, missing
server and security requirement errors, query override parsing with trimming
and boolean validation, authentication-source selector mapping, distinct
security-scheme import with base identity-provider precedence, obsolete
operation cleanup, and empty operation/middleware pruning. This evidence does
not claim full OpenAPI import correctness, OpenAPI security evaluation
semantics, gateway authentication enforcement, route generation, request
matching, request validation execution, allow-list enforcement, mock-response
execution, middleware execution, upstream availability, gateway API loading,
persistence, analytics, or final client-visible runtime behavior.

`SW-REQ-089` owns the concrete `apidef/oas/middleware.go` middleware helper
shapes. Its evidence covers aggregate global middleware Fill/ExtractTo
conversion, plugin configuration data and bundles, CORS, global cache options,
global request and response header transforms, context variables, traffic-log
analytics plugin and retention conversion, global request-size limits,
ignore-case and skip flags, deprecated singular plugin JSON migration to plural
plugin arrays, path-level allow/block/ignore-authentication/method-transform/
cache/enforced-timeout extraction, HTTP method helper selection, MCP primitive
mock detection and ExtendedPaths extraction boundaries, scalar allowance,
transform, cache, timeout, custom plugin, virtual endpoint, endpoint post
plugin, circuit-breaker, request-size, context-variable, and ignore-case helper
conversion, nil optional helper boundaries, and endpoint cache default timeout
behavior. This evidence does not claim actual gateway middleware execution,
route matching, authentication enforcement, CORS enforcement, cache storage
behavior, runtime header mutation, virtual endpoint JavaScript execution, Go
plugin loading or execution, analytics delivery, traffic-log persistence,
circuit-breaker runtime behavior, request-size enforcement, MCP JSON-RPC
execution, gateway API loading, route generation, request admission,
persistence backend correctness, or final client-visible runtime behavior.

`SW-REQ-090` owns the concrete `apidef/oas/oas.go` root document helpers. Its
evidence covers x-tyk-api-gateway and x-tyk-streaming extension lifecycle
helpers, JSON marshalling and clone behavior, eager typed initialization of
lazy extension and security-scheme caches, typed authentication,
security-scheme, middleware, and operation accessors, local server
add/remove/update/replace helpers, validation and normalization coordination,
required-field defaulting, selected Classic compatibility clearing, and
validation-option derivation from OAS configuration. This evidence does not
claim full OpenAPI import/export correctness, OpenAPI specification
completeness, gateway API loading, route generation, request matching, request
admission, runtime authentication enforcement, runtime middleware execution,
upstream availability, persistence backend correctness, analytics, or final
client-visible behavior.

`SW-REQ-091` owns the concrete `apidef/oas/operation.go` operation document
helpers. Its evidence covers operation middleware containers, operation-level
import coordination from Tyk extension configuration parameters, Classic
ExtendedPaths fill/extract orchestration for operation-scoped support shapes,
regex and mux-template path normalization into OpenAPI path parameters,
deterministic operation ID creation and existing operation preservation,
validate-request schema conversion and import gating, mock-response metadata
conversion and OAS-example import gating, mock response content-type detection,
deterministic mock allow-list ordering, and nil-safe primitive extraction. This
evidence does not claim gateway routing, request matching, request admission,
runtime middleware execution, request validation execution, mock-response
execution, upstream availability, persistence, analytics, or final
client-visible behavior.

`SW-REQ-092` owns the concrete `apidef/oas/security.go` security document
helpers. Its evidence covers token, JWT, basic, OAuth, and external-OAuth
helper shapes; import and normalization defaults for authentication helper
structs; JWT validation, introspection, introspection-cache, notification, and
request-body credential extraction shape conversion; API-key and OAuth
OpenAPI security-scheme construction and extraction; Tyk proprietary auth
classification; OAS versus vendor-extension security requirement partitioning
and recombination; aggregate Classic API definition security fill/extract
coordination; JWT configuration lookup across legacy and compliant security
processing modes; and Classic security-field reset behavior. This evidence
does not claim token validation, signature verification, certificate
validation, OAuth/OIDC provider execution, custom plugin execution, OpenAPI
security evaluation semantics, gateway request admission, persistence,
analytics, or final runtime authentication behavior.

`SW-REQ-093` owns the concrete `apidef/oas/upstream.go` upstream document
helpers. Its evidence covers aggregate upstream fill/extract coordination;
service-discovery and service-discovery-cache support-shape conversion;
uptime-test support-shape conversion, command preservation, and
protocol/check-URL normalization; upstream mutual-TLS and certificate-pinning
mapping conversion; API-level rate-limit metadata conversion; TLS transport
version, cipher, proxy URL, insecure-skip-verify, and common-name-check
conversion; internal proxy metadata conversion; upstream basic authentication,
OAuth client-credentials, OAuth password authentication, and request-signing
support-shape conversion; load-balancing target-weight aggregation,
deterministic ordering, zero-weight target preservation, and weighted Classic
target expansion; and preserve-host-header and preserve-trailing-slash flag
conversion. This evidence does not claim runtime proxying, service discovery
execution, health-check execution, TLS handshake behavior, certificate
validation, public-key validation, rate-limit enforcement, upstream
authentication execution, request signing cryptography, load-balancer traffic
distribution, gateway request admission, persistence, analytics, or final
client-visible behavior.

`SW-REQ-094` owns the concrete
`apidef/streams/bento/schema/generate_bento_config_schema.go` Bento
configuration schema generator. Its evidence covers selected top-level Bento
schema property copying, processor and scanner definition retention, supported
input/output source insertion from Bento `allOf`/`anyOf` fragments,
unsupported source omission, deterministic indented JSON file writing, custom
validation rule application with rule-name error wrapping, URI format metadata
insertion into input and output `http_client` URL schema sections, selected
help/output CLI flag handling for successful command paths, and controlled
errors for malformed helper input, malformed rule targets, rule failures,
invalid JSON output state, and invalid output paths. This evidence does not
claim Bento schema completeness, Bento component correctness, stream
configuration validation, stream runtime execution, gateway API loading, route
generation, request matching, gateway request admission, persistence,
analytics, or final client-visible behavior.

`SW-REQ-086` owns the concrete `apidef/notifications.go` notification helper.
Its evidence covers bounded HTTP client construction, notification manager
wire fields, empty URL no-op behavior, retry-limit stopping behavior, JSON POST
request creation, user-agent/content-type/shared-secret headers, successful
send behavior, and handled marshal, request-construction, transport,
response-body read, and non-200 response failures. This evidence does not
claim OAuth manager correctness, asynchronous goroutine scheduling, external
endpoint availability, durable delivery, retry backoff timing accuracy, log
delivery, gateway API loading, route generation, request matching, gateway
request admission, authentication execution, persistence, analytics, or final
client-visible runtime behavior.

`SW-REQ-085` owns the concrete `apidef/migration.go` Classic API definition
migration helpers. Its evidence covers old-to-new versioning migration error
handling, deterministic base/child API split behavior apart from generated
child API IDs, endpoint method-action expansion into method-specific endpoint
metadata and mock-response metadata, simple-to-advanced cache migration,
authentication config pruning and naming, legacy custom plugin auth migration,
plugin bundle/config, mutual TLS, certificate pinning, gateway tag,
authentication plugin, ID extractor, custom domain, scope-to-policy,
response-processor, global header, global response-header, global rate-limit,
and IP access-control compatibility shape migration, plus disabled default
initialization for OAS-origin Classic API definitions. This evidence does not
claim full API import correctness, persistence migration correctness, dashboard
migration orchestration, gateway API loading, route generation, request
matching, gateway request admission, middleware execution, authentication
execution, upstream availability, analytics, or final client-visible runtime
behavior.

`SW-REQ-081` owns the concrete `apidef/importer/blueprint.go` Apiary Blueprint
importer conversion behavior. Its evidence covers JSON load success and
malformed JSON errors, missing resource-group and empty resource errors,
conversion of Blueprint resources into Classic API version whitelist metadata,
preservation of multiple converted resources and response headers, method
action selection for mock and non-mock imports, response body and status-code
mapping, HTTP 200 fallback for non-numeric Blueprint response names, skipping
actions without response examples, version insertion into API definitions, and
deterministic active keyless API-definition versioning/proxy shape apart from
generated API IDs. This evidence does not claim API Blueprint specification
completeness, semantic validation of Blueprint parameters or schemas, upstream
availability, gateway API loading, route generation, request matching, gateway
request admission, mock-response middleware execution, persistence, analytics,
or final client-visible runtime behavior.

`SW-REQ-082` owns the concrete `apidef/importer/importer.go` source dispatcher
and importer interface shape. Its evidence covers supported source selection
for Apiary Blueprint, Swagger, and WSDL, fresh concrete importer allocation for
repeated equivalent requests, deterministic returned importer types, and
unsupported source rejection with no importer and an explicit error. This
evidence does not claim Blueprint, Swagger, or WSDL parse or conversion
correctness, gateway API loading, route generation, request matching, gateway
request admission, persistence, analytics, or final client-visible runtime
behavior.

`SW-REQ-083` owns the concrete `apidef/importer/swagger.go` Swagger importer
conversion behavior. Its evidence covers JSON load success and malformed JSON
errors, empty path-set errors, unsupported direct mock-version conversion,
conversion of defined Swagger path methods into Classic API whitelist and
track-endpoint metadata, deterministic path and method ordering, skipping paths
without defined methods, version insertion into API definitions, top-level
API-definition build behavior that ignores the unsupported mock flag, and
deterministic active keyless API-definition versioning/proxy shape apart from
generated API IDs. This evidence does not claim Swagger/OpenAPI specification
completeness, semantic validation of schemas or response objects, mock import
support, upstream availability, gateway API loading, route generation, request
matching, gateway request admission, persistence, analytics, or final
client-visible runtime behavior.

`SW-REQ-084` owns the concrete `apidef/importer/wsdl.go` WSDL importer
conversion behavior. Its evidence covers WSDL 1.1 load success, malformed-root
and WSDL 2.0 rejection, per-importer service-port mapping isolation, SOAP 1.1,
SOAP 1.2, and HTTP binding conversion into Classic API track-endpoint and
URL-rewrite metadata, HTTP urlReplacement wildcard conversion, unsupported
transport and malformed service-shape errors without panics, version insertion
into API definitions, top-level API-definition build behavior that ignores the
unsupported mock flag, and deterministic active keyless API-definition
versioning/proxy shape apart from generated API IDs. This evidence does not
claim complete WSDL specification support, WSDL 2.0 support, full XML schema or
message validation, regex escaping semantics for arbitrary HTTP endpoint
metacharacters, partial multi-service failure semantics, mock import support,
upstream availability, gateway API loading, route generation, request matching,
gateway request admission, persistence, analytics, or final client-visible
runtime behavior.
