# Development Configuration Requirements Evidence

<!-- documents STK-REQ-030 SYS-REQ-118 SW-REQ-105 -->

`STK-REQ-030`, `SYS-REQ-118`, and `SW-REQ-105` cover local
`config/development.go` and `config/development_off.go` build-tag-specific
configuration helper behavior.

The executable evidence is `config/development_test.go` under the `dev` build
tag and `config/development_off_test.go` under the default non-`dev` build. It
covers development builds falling back to default storage when custom rate
limiter storage is disabled or absent, development builds selecting configured
rate limiter storage when enabled and present, and release builds always using
the default gateway storage configuration.

This evidence does not claim rate limiter algorithm behavior, Redis
connectivity, distributed storage behavior, gateway request admission, or final
client-visible runtime behavior.
