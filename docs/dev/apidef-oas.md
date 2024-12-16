# Translating Tyk OAS API Definition to Tyk Classic API Definition (and vice versa)

To ensure feature parity between Tyk OAS APIs and Tyk classic API definitions, follow these steps:

## Step 1: Define Required Structs

Define the required structs or add the required fields in the `apidef/oas` package.

## Step 2: Use camelCase Notation

Ensure OAS fields follow `camelCase` notation for `json` and `bson` tags.

## Step 3: Handle Required Fields

For fields that are required:

3.1. Remove `omitempty` from struct tags.
3.2. Avoid using pointer types for required fields.

## Step 4: Handle Optional Fields

For optional fields:

### 4.1. Add the `omitempty` tag.

### 4.2. Use pointer types for structs.

## Step 5: Add Go Doc Comments

Add comments in Go doc format for each field to enable automated documentation generation.

## Step 6: Implement Fill and ExtractTo Methods

Every struct type should follow the convention of having `Fill(apidef.APIDefinition)` and `ExtractTo(*apidef.APIDefinition)` methods:

### 6.1. `Fill` populates the struct from a classic API definition.

### 6.2. `ExtractTo` extracts the contents of an OAS API definition into a classic API definition.

## Step 7: Implement Fill Method Pattern

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

## Step 8: Implement ExtractTo Method Pattern

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

## Step 9: Write Tests

Write tests for conversion functions. Refer to the example:
https://github.com/TykTechnologies/tyk/pull/5979/files#diff-222cc254c0c6c09fa0cf50087860b837a0873e2aef3c84ec7d80b1014c149057R97

## Step 10: Update TestOAS_ExtractTo_ResetAPIDefinition

Maintain and update the list of fields that are not OAS compatible in the `TestOAS_ExtractTo_ResetAPIDefinition` test.

## Step 11: Update JSON Schema

Update the JSON schema for the `x-tyk-api-gateway` struct in:
https://github.com/TykTechnologies/tyk/blob/master/apidef/oas/schema/x-tyk-api-gateway.json

Ensure this schema is updated whenever the OAS API definition is modified.