<!-- documents STK-REQ-069 SYS-REQ-157 SW-REQ-144 -->

`STK-REQ-069`, `SYS-REQ-157`, and `SW-REQ-144` cover local user session
metadata helper behavior in `user/custom_policies.go` and
`user/session_tags.go`.

The executable evidence is `user/custom_policies_test.go` and
`user/session_tags_test.go`. It covers custom policy extraction failures for
missing, nil, wrong-type, and malformed policy metadata; empty and populated
policy metadata; ordered `GetCustomPolicies` output; ID-keyed `CustomPolicies`
output; `SetCustomPolicies` metadata initialization and roundtrip behavior; and
metadata tag copying for developer ID, rate-limit pattern, tags, and policies
including no-op inputs and unsupported tag element filtering.

This evidence does not claim policy merge behavior, gateway session lookup,
persistence backends, authorization decisions, or final client responses.
