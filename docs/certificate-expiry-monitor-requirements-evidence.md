# Certificate Expiry Monitor Requirements Evidence

<!-- documents STK-REQ-042 SYS-REQ-130 SW-REQ-117 -->

`STK-REQ-042`, `SYS-REQ-130`, and `SW-REQ-117` cover local
`internal/certcheck` helper behavior.

The executable evidence is `internal/certcheck/certcheck_reqproof_test.go`.
It covers batch deduplication and draining, certificate expiry/expiring-soon
classification, default monitor configuration application, certificate role
selection, event metadata/message construction, duration helper conversion, and
local in-memory cooldown-cache behavior.

This evidence does not claim certificate discovery or loading, Redis
availability or distributed TTL correctness, background scheduler fairness,
external event-bus delivery, gateway alerting semantics, client-visible gateway
behavior, or final certificate trust and transport-security outcomes.
