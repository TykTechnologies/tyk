# Gateway Configuration Requirements Evidence

<!-- documents STK-REQ-028 SYS-REQ-116 SW-REQ-103 -->

`STK-REQ-028`, `SYS-REQ-116`, and `SW-REQ-103` cover local
`config/config.go` gateway configuration helper behavior.

The executable evidence is `config/config_test.go`. It covers default values
and `WriteDefault`, ordered configuration file loading and missing-file errors,
environment override behavior, deprecated/current event-trigger fields,
custom certificate, secret, labs, and port-whitelist decoders, ignored-IP
analytics decisions, certificate expiry monitor defaults and overrides, and
tracing/OpenTelemetry JSON/env parsing plus round trips.

This evidence does not claim full gateway runtime interpretation of every
configuration field, network binding, storage connectivity, analytics delivery,
tracing export delivery, API loading, request admission, or final
client-visible runtime behavior.
