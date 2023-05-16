# Schema

Tyk generally has the following data models:

- config
- apidef
- apidef/oas
- management apis

The management APIs are documented in `/swagger.yml`. The implementation
in code may be inlined and there is no source of truth available for them.

For the remaining data models defined in Go, we generate:

- `jsonschema` - auto generated jsonschema from go structures,
- `structs` - a representation of go source code with full details.

These documents are generated from source code, and can be used to
provide additional functionality:

- `jsonschema` can be used to validate any config, apidef or oas extension json,
- `structs` can be used as a source for code or documentation generation
    - `structs/config.json` and `config-defaults.json` can be used to generate documentation,
    - `structs/apidef.jgon` can be used to generate a dependency-free apidef package

With time, we could generate code for the management APIs. Once that is
in place, we can reuse the generators already existing. The above gives
everyone access to a machine-readable format that describes the gateway
data model. In the past, this information was only available by parsing
source code (tyk-docs generator, infamously).

The management APIs could, with time, also generate source code. Once the
source code is generated, the pre-existing `.go` -> `.json` generators
can be reused.

# Updating the schema

1. Navigate to `internal/`,
2. Run `task schema-gen`.

If you want to run it without task:

1. `go run internal/cmd/schema-gen/main.go` (from root).
