# Translating Tyk OAS API Definition to Tyk Classic API Definition (and vice versa)

To ensure feature parity between Tyk OAS APIs and Tyk classic API definitions, follow these guidelines:

## Define necessary Structs

Define the necessary structs or add the necessary fields in the `apidef/oas` package.

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

 1. Add the `omitempty` tag.

 2. Use pointer types for structs.

## Add Go Doc Comments

Add comments in Go doc format for each field to enable automated documentation generation.

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

## Write Tests

Write tests for conversion functions. Refer to the example:
https://github.com/TykTechnologies/tyk/pull/5979/files#diff-222cc254c0c6c09fa0cf50087860b837a0873e2aef3c84ec7d80b1014c149057R97

## Update TestOAS_ExtractTo_ResetAPIDefinition

Maintain and update the list of fields that are not OAS compatible in the `TestOAS_ExtractTo_ResetAPIDefinition` test.

## Update JSON Schema

Update the JSON schema for the `x-tyk-api-gateway` struct in:
https://github.com/TykTechnologies/tyk/blob/master/apidef/oas/schema/x-tyk-api-gateway.json

Ensure this schema is updated whenever the OAS API definition is modified.