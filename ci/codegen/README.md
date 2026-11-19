# Client code generation from swagger.yml

Generator configs for [openapi-generator](https://openapi-generator.tech) (7.x).
One config per language. They carry the settings needed for the generated
client to compile; `swagger.yml` alone is not enough (TT-18852). The Dashboard
repository has the same layout for its own swagger (TT-18403).

```bash
openapi-generator-cli generate -i swagger.yml -c ci/codegen/<lang>.yaml -o <out-dir>
```

`check.sh` generates all four clients with these configs and compiles them.
CI runs it on every change to `swagger.yml` (`lint-swagger.yml`, job
`codegen_check`). Locally:

```bash
ci/codegen/check.sh swagger.yml
```

What the configs do and why:

- `nameMappings: {_id: MongoId}` (all languages). `Policy` has both `_id` and
  `id`. Both become `Id` / `id` in Go and Java and the client does not compile.
  The mapping renames the generated field only; the JSON key on the wire stays
  `_id`.
- `modelNameMappings: {ServerVariable: OASServerVariable}` (Go). The OAS 3.0
  meta-schema pulled in through `3.0.json` defines `ServerVariable`, which
  clashes with the `ServerVariable` type the Go generator ships in
  `configuration.go`.

The inline `oneOf` in `TraceRequest.oas` needs no mapping: openapi-generator
7.26 synthesizes a `TraceRequestOas` model for it in every language.
