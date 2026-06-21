<!-- documents STK-REQ-096 SYS-REQ-184 SW-REQ-171 -->

`STK-REQ-096`, `SYS-REQ-184`, and `SW-REQ-171` cover local key-value store
adapter behavior in `storage/kv`.

The executable evidence is `storage/kv/*_test.go`. It covers Store interface
conformance, Consul client construction from configuration, Consul missing-key,
get, and put behavior through a local HTTP test server, Vault client
construction and token configuration, Vault v1 and v2 get/put path and payload
behavior, Vault key-format validation, missing-token rejection, and Vault
ReadSecret success, missing, and server-error paths.

This evidence does not claim real Consul or Vault service availability,
distributed durability, authentication or ACL correctness, TLS validation,
secret encryption, production network behavior, gateway configuration loading,
or final client-visible behavior beyond the focused key-value adapter tests.
