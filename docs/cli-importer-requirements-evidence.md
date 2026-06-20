# CLI Importer Requirements Evidence

<!-- documents STK-REQ-026 SYS-REQ-114 SW-REQ-101 -->

`STK-REQ-026`, `SYS-REQ-114`, and `SW-REQ-101` cover only the local
`cli/importer/importer.go` command wrapper.

The executable evidence is `cli/importer/importer_reqproof_test.go`. It covers
command registration and flag binding for the import command, create-API and
version-insert input validation, valid WSDL service:port mapping, local API
definition JSON load/decode success and error paths, Blueprint/Swagger/WSDL
loader selection and missing-file errors, and printed API definition JSON
formatting that removes the empty BSON-only `id` field.

This evidence intentionally does not claim full Blueprint, Swagger, or WSDL
conversion correctness. Those conversion engines are covered by the existing
`apidef/importer` requirements. This evidence also does not claim gateway API
loading, route generation, request matching, gateway request admission,
persistence, analytics, or final client-visible runtime behavior.

Malformed `--port-names` strings without `service:port` separators are outside
this requirement's claim; the covered behavior is valid service:port mapping.
