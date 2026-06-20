# CLI Command Surface Requirements Evidence

<!-- documents STK-REQ-047 SYS-REQ-135 SW-REQ-122 -->

`STK-REQ-047`, `SYS-REQ-135`, and `SW-REQ-122` cover only local CLI command
surface behavior in `cli/cli.go`, `cli/plugin/plugin.go`, and
`cli/version/version.go`.

The executable evidence is split across focused package tests:

- `cli/cli_reqproof_test.go` covers one-time top-level command setup, start
  flag registration, start flag parsing, and `Parse` dispatch through the
  configured Kingpin application.
- `cli/plugin/plugin_reqproof_test.go` covers local plugin load command
  registration, file/symbol flag binding, explicit local plugin load errors,
  and panic-to-error conversion in the loader wrapper.
- `cli/version/version_reqproof_test.go` covers deterministic text output,
  JSON output, and version command registration.

This proof slice does not claim gateway startup behavior, configuration file
semantics, real plugin execution, plugin runtime safety, gateway middleware
effects, process exit behavior for other commands, persistence, network
binding, analytics, or final client-visible gateway behavior.
