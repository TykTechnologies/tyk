# Configuration Utility Requirements Evidence

<!-- documents STK-REQ-034 SYS-REQ-122 SW-REQ-109 -->

`STK-REQ-034`, `SYS-REQ-122`, and `SW-REQ-109` cover local
`config/util.go` configuration utility helper behavior.

The executable evidence is `config/util_test.go`. It covers discovered
`tyk.conf` loading, environment fallback when the config file is absent,
default cloning with environment overrides, file discovery success and
not-found errors, and storage host address assembly precedence.

This evidence does not claim full gateway startup behavior, all configuration
field semantics, storage connectivity, Redis dialing, filesystem permission
recovery outside local file discovery, or final gateway runtime behavior.
