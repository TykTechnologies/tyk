# API Definition Requirements Evidence

<!-- documents SYS-REQ-104 -->
<!-- documents SW-REQ-019 -->
<!-- documents SW-REQ-020 -->
<!-- documents SW-REQ-021 -->
<!-- documents SW-REQ-033 -->

This document records the first API-definition support-model proof slice. The
slice is deliberately limited to small `apidef` helper models and does not claim
API import, OAS conversion, route generation, gateway request admission, or the
full API definition lifecycle.

`SYS-REQ-104` covers API-definition support model helpers that preserve typed
health-check wire values, host-list access behavior, and error-override helper
state without silent data-shape drift.

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
