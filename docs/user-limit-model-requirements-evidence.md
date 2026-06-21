<!-- documents STK-REQ-070 SYS-REQ-158 SW-REQ-145 -->

`STK-REQ-070`, `SYS-REQ-158`, and `SW-REQ-145` cover local user limit model
helper behavior in `user/session.go` and `user/policy.go`.

The executable evidence is `user/session_test.go` and
`user/limit_model_reqproof_test.go`. It covers rate duration calculation and
disabled zero-duration paths; APILimit empty and IsZero classification;
RateLimit IsZero classification; APILimit clone value preservation and smoothing
deep-copy behavior; APILimit configured quota/throttle predicates; policy and
session APILimit derivation; policy active-quota, non-negative-quota, configured
rate, and configured throttle predicates; and policy partition enablement.

This evidence does not claim policy merge behavior, gateway enforcement,
persistence backends, quota accounting, runtime rate limiting execution, or final
client responses.
