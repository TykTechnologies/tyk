<!-- documents STK-REQ-065 SYS-REQ-153 SW-REQ-140 -->

`STK-REQ-065`, `SYS-REQ-153`, and `SW-REQ-140` cover local gateway error
override helper behavior in `gateway/error_overrides.go`.

The executable evidence is `gateway/error_overrides_test.go`. It covers nil and
empty override handling, valid and invalid rule compilation, exact and prefix
status-code indexing, API-before-gateway override precedence, flag and
message-pattern matching, body-field matching, inline and file template
selection, direct-body and default-template classification, upstream response
matching, lazy body need detection, and override-result construction.

This evidence does not claim response middleware execution, final HTTP response
writing, route handling, gateway request admission, analytics, persistence, or
client-visible behavior.
