# Translating Tyk OAS API Definition to Tyk Classic API Definition (and vice versa)

To ensure feature parity between Tyk OAS APIs and Tyk classic API definitions, follow these guidelines:

## Define necessary Structs

Define the necessary structs or add the necessary fields in the `apidef/oas` package.

Make sure `json` and `bson` tags are added to the fields.

If an `enabled` flag is specified in the OAS contract, make sure a corresponding `disabled` or `enabled` flag is added in the classic API definition.

Also make sure that `disabled`/`enabled` flag toggles the feature on or off.

### Why `disabled` or `enabled` in classic API definition?

Historically, almost every feature/middleware in Tyk is considered enabled by default when value for feature controls are non zero values. It is disabled when the feature controls are having zero values. For this reason, whenever an existing feature is migrated to OAS, and OAS has an `enabled` flag then a `disabled` flag is added to give explicit control to turn off the feature.

Please also make sure that the disabled flags are set to true in `APIDefinition.SetDisabledFlags()`, so that it is not enabled in OAS by default.

## Use camelCase Notation

Ensure OAS fields follow `camelCase` notation for `json` and `bson` tags.

## Handle Required Fields

For fields that are required:

1. Do not use `omitempty` in struct tags.

2. Do not use pointer types for required fields.

3. Add a comment `// required` towards the end of a required field so that automation generates docs accordingly.

4. As a convention, we also try to add the corresponding classic API definition fields in godoc in the following format

   ```
   // Tyk classic API definition: `!use_keyless`.
   ```

   This might not be perfect at this moment, but we aim to keep this link so that customers find it easier to follow the docs.

## Handle Optional Fields

For optional fields:

1. Add the `omitempty` tag

2. Use pointer types for structs.

3. Make sure that `omitempty` tag is added for slice fields that are optional.

## Add Go Doc Comments

Add comments in Go doc format for each field to enable automated documentation generation (this is validated by linter).

## Implement Fill and ExtractTo Methods

Every OAS struct should follow the convention of having `Fill(apidef.APIDefinition)` and `ExtractTo(*apidef.APIDefinition)` methods:

`Fill` populates the struct from a classic API definition.

`ExtractTo` extracts the contents of an OAS API definition into a classic API definition.

## Implement Fill Method Pattern

Each `Fill` method should follow this pattern:

```go
if u.RateLimit == nil {
	u.RateLimit = &RateLimit{}
}

u.RateLimit.Fill(api)
if ShouldOmit(u.RateLimit) {
	u.RateLimit = nil
}
```

This ensures the field is reset to empty when not configured in the classic API definition.

### Working with `VersionData`

A `Main` version will be provided that can be used for `Fill`.

```go
api.VersionData.Versions[Main]
```

## Implement ExtractTo Method Pattern

Similarly, follow this pattern with `ExtractTo`:

```go
if u.RateLimit == nil {
	u.RateLimit = &RateLimit{}
	defer func() {
		u.RateLimit = nil
	}()
}

u.RateLimit.ExtractTo(api)
```

### Working with `VersionData`

There are 2 helper functions for `ExtractTo` that will help to handle `VersionData`. You can use them like this:

```go
func (g *GlobalRequestSizeLimit) ExtractTo(api *apidef.APIDefinition) {
	mainVersion := requireMainVersion(api)
	defer func() {
		updateMainVersion(api, mainVersion)
	}()

	// manipulate the Main VersionInfo here
}
```

## Write Tests

Write tests for conversion functions. Refer to the example: https://github.com/TykTechnologies/tyk/pull/5979/files#diff-222cc254c0c6c09fa0cf50087860b837a0873e2aef3c84ec7d80b1014c149057R97

## Update TestOAS_ExtractTo_ResetAPIDefinition

Maintain and update the list of fields that are not OAS compatible in the `TestOAS_ExtractTo_ResetAPIDefinition` test.

## Update JSON Schema

Update the JSON schema for the `x-tyk-api-gateway` struct in: https://github.com/TykTechnologies/tyk/blob/master/apidef/oas/schema/x-tyk-api-gateway.json

Ensure this schema is updated whenever the OAS API definition is modified.
