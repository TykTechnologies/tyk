# Checkup Requirements Evidence

<!-- documents STK-REQ-024 SYS-REQ-112 SW-REQ-099 -->

This document records the startup checkup proof slice. The slice is limited to
local `checkup` package startup configuration diagnostic behavior and does not
claim operating-system resource tuning, log transport delivery, operator
remediation, gateway request admission, analytics pipeline durability, or final
client-visible behavior.

`STK-REQ-024` owns the stakeholder need for startup diagnostics that expose
risky local configuration and deterministic analytics defaults.

`SYS-REQ-112` owns the system-level startup checkup support contract. Its
evidence covers warning emission for insecure configuration allowance,
deprecated health checks, missing global session lifetime, retained default
gateway and node secrets, unset analytics pool size, undersized analytics
records buffer, and zero analytics storage expiration. It also covers preserving
analytics values when analytics is disabled, defaulting analytics values when
analytics is enabled, preserving sufficient analytics values, public `Run`
orchestration, and host resource probe execution without mutation claims.

`SW-REQ-099` owns the concrete `checkup/checkup.go` helper behavior. Its
evidence is the focused `checkup/checkup_reqproof_test.go` suite. Host CPU and
file-descriptor checks are intentionally verified only as local probe execution
because their warning paths depend on the machine running the test.
