<!-- documents STK-REQ-071 SYS-REQ-159 SW-REQ-146 -->

`STK-REQ-071`, `SYS-REQ-159`, and `SW-REQ-146` cover local user session state
helper behavior in `user/session.go`.

The executable evidence is `user/session_test.go` and
`user/session_state_reqproof_test.go`. It covers supported and unsupported hash
type classification, empty session construction, modified flag transitions and
JSON reset behavior, collection clone independence, stable MD5 output for an
unchanged session, key-hash set/get/empty behavior and missing-cache panic,
policy ID fallback and assignment, order-independent policy ID comparison for
unique policy ID sets, per-API and session quota-limit selection, basic-auth
detection, active-at classification, and consumed-quota classification.

This evidence does not claim policy merge behavior, gateway authentication,
persistence backends, runtime quota enforcement, session lifetime expiration
behavior, endpoint limit conversion, or final client responses.
