# OAS Package

This package provides support for OpenAPI Specification (OAS) schema validation and integration with Tyk's custom extensions.

## Overview

The OAS package handles:
- Loading and validating OAS schemas (3.0, 3.1, and future versions)
- Injecting Tyk-specific extensions (`x-tyk-api-gateway`) into OAS schemas
- Validating OAS documents and templates against schemas
- Managing schema versions and defaults

## How to Add a New OAS Version

When a new OAS version is released (e.g., OAS 4.0), follow these steps to add support:

### Step 1: Add the OAS Schema File

1. Download or create the official JSON Schema for the new OAS version
2. Save it to `apidef/oas/schema/` directory with the naming convention: `{major}.{minor}.json`
   - Example: `3.1.json` for OAS 3.1.x
   - Example: `4.0.json` for OAS 4.0.x

```bash
# Example
curl -o apidef/oas/schema/4.0.json https://spec.openapis.org/oas/4.0/schema/...
```

### Step 2: Understand Schema Structure Differences

Different OAS/JSON Schema versions may use different keys for definitions:

- **OAS 3.0** uses `"definitions"` (JSON Schema Draft 04)
- **OAS 3.1+** uses `"$defs"` (JSON Schema 2020-12)
- **Future versions** may introduce new keys

Check the schema file to identify which key is used:

```bash
# Check for definitions key
grep -E '"definitions"|"\$defs"' apidef/oas/schema/4.0.json | head -5
```

### Step 3: Update Code (if needed)

The code is designed to automatically detect and handle different definition keys using the `GetDefinitionsKey()` function.

**If the new version uses an existing key (`definitions` or `$defs`):**
- ✅ No code changes needed! The schema will load automatically.

**If the new version uses a NEW key (e.g., `$schemas`):**
- Update the `GetDefinitionsKey()` function in `validator.go` to detect the new key:

```go
func GetDefinitionsKey(schemaData []byte) string {
    // Try newest format first
    if _, _, _, err := jsonparser.Get(schemaData, "new-key"); err == nil {
        return "new-key"
    }
    // Try OAS 3.1+ format
    if _, _, _, err := jsonparser.Get(schemaData, keyDefs); err == nil {
        return keyDefs
    }
    // Fall back to OAS 3.0 format
    return keyDefinitions
}
```

### Step 4: Add Tests

Add comprehensive tests to ensure the new schema loads correctly:

#### 4.1 Update `Test_loadOASSchema`

The test will automatically verify the new version if the schema file exists. It:
- Checks that the schema loads
- Verifies x-tyk extensions are injected correctly
- Validates the correct definitions key is used

#### 4.2 Add Version-Specific Validation Test

Create a new test function to validate documents with the new version:

```go
func TestValidateOASObject_4_0(t *testing.T) {
    t.Parallel()
    
    // Create minimal valid OAS 4.0 document
    validOAS40Doc := []byte(`{
        "openapi": "4.0.0",
        "info": {
            "title": "Test API 4.0",
            "version": "1.0.0"
        },
        "paths": {
            "/test": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "Success"
                        }
                    }
                }
            }
        },
        "x-tyk-api-gateway": {
            "info": {
                "name": "test-api-4.0",
                "state": {
                    "active": true
                }
            },
            "upstream": {
                "url": "http://localhost:8080"
            },
            "server": {
                "listenPath": {
                    "value": "/test-api-4.0/"
                }
            }
        }
    }`)

    t.Run("valid OAS 4.0 document with version 4.0.0", func(t *testing.T) {
        t.Parallel()
        err := ValidateOASObject(validOAS40Doc, "4.0.0")
        assert.NoError(t, err)
    })

    t.Run("valid OAS 4.0 document with version 4.0", func(t *testing.T) {
        t.Parallel()
        err := ValidateOASObject(validOAS40Doc, "4.0")
        assert.NoError(t, err)
    })
}
```

#### 4.3 Add Template Validation Test

```go
func TestValidateOASTemplate_4_0(t *testing.T) {
    t.Parallel()

    // Minimal OAS 4.0 template (missing required x-tyk fields)
    template40 := []byte(`{
        "openapi": "4.0.0",
        "info": {
            "title": "Template API 4.0",
            "version": "1.0.0"
        },
        "paths": {},
        "x-tyk-api-gateway": {}
    }`)

    t.Run("valid OAS 4.0 template", func(t *testing.T) {
        t.Parallel()
        err := ValidateOASTemplate(template40, "4.0")
        assert.NoError(t, err)
    })
}
```

#### 4.4 Add Schema Retrieval Test

Update `TestGetOASSchema` with new test cases:

```go
t.Run("return 4.0 schema when version 4.0 is requested", func(t *testing.T) {
    schema, err := GetOASSchema("4.0")
    assert.NoError(t, err)
    assert.NotEmpty(t, schema)
    
    // Verify it's the 4.0 schema by checking the definitions key
    defsKey := GetDefinitionsKey(schema)
    assert.Equal(t, "expected-key", defsKey, "OAS 4.0 should use 'expected-key'")
})

t.Run("return 4.0 schema when version 4.0.0 is requested", func(t *testing.T) {
    schema, err := GetOASSchema("4.0.0")
    assert.NoError(t, err)
    assert.NotEmpty(t, schema)
    
    defsKey := GetDefinitionsKey(schema)
    assert.Equal(t, "expected-key", defsKey)
})
```

### Step 5: Run Tests

Run all tests to ensure the new version works correctly:

```bash
# Run all OAS package tests
cd apidef/oas
go test -v

# Run specific tests
go test -v -run "Test_loadOASSchema|TestValidateOASObject_4_0|TestGetOASSchema"
```

### Step 6: Update Default Version (Optional)

The default OAS version is controlled in the `setDefaultVersion()` function in `validator.go`.

**To keep the current default version:**
- ✅ No changes needed. The code will automatically prefer the older version for stability.

**To make the new version the default:**
- Update or remove the override logic in `setDefaultVersion()`:

```go
func setDefaultVersion() {
    var versions []string
    for k := range oasJSONSchemas {
        versions = append(versions, k)
    }

    latestVersion := findDefaultVersion(versions)

    // Remove or update this override when ready to use newer version
    if latestVersion == "4.0" {
        defaultVersion = "3.0"  // Keep 3.0 as default for now
    } else {
        defaultVersion = latestVersion
    }
}
```

### Step 7: Document Breaking Changes

If the new OAS version has breaking changes or requires updates to existing code:

1. Document the changes in the main project CHANGELOG
2. Add migration notes for users upgrading to the new version
3. Update examples and documentation to use the new version (if applicable)

## Example: Adding OAS 3.1 Support

Here's what was done to add OAS 3.1 support:

1. ✅ Added `schema/3.1.json` file
2. ✅ Identified that OAS 3.1 uses `$defs` instead of `definitions`
3. ✅ Updated `GetDefinitionsKey()` to detect `$defs`
4. ✅ Updated `loadOASSchema()` to use detected key
5. ✅ Updated `ValidateOASTemplate()` to use detected key
6. ✅ Added comprehensive tests:
   - `TestGetDefinitionsKey` - Tests the helper function
   - `TestValidateOASObject_3_1` - Tests validation of 3.1 documents
   - `TestValidateOASTemplate_3_1` - Tests template validation
   - Updated `Test_loadOASSchema` - Verifies both 3.0 and 3.1
   - Updated `TestGetOASSchema` - Added 3.1 retrieval tests
7. ✅ Kept default version at 3.0 for stability
8. ✅ All tests pass ✅

## Key Architecture Decisions

### Automatic Schema Detection
The `GetDefinitionsKey()` function automatically detects which key a schema uses, making the code robust across versions.

### Public API
`GetDefinitionsKey()` is a public function, allowing other products to leverage this detection logic.

### Version Management
- Schemas are stored by minor version (e.g., `3.0`, `3.1`)
- Patch versions (e.g., `3.1.2`) map to their minor version
- Default version can be overridden for stability during transitions

### Schema Injection
X-Tyk extensions are injected from `schema/x-tyk-api-gateway.json` into each OAS schema during load time, ensuring all schemas have consistent Tyk-specific validation.

## Troubleshooting

### Schema Not Loading
**Problem:** New schema file is not being loaded.

**Solutions:**
- Ensure filename follows the pattern `{major}.{minor}.json`
- Verify the file is valid JSON
- Check that the file is in the `schema/` directory
- Ensure the file is included in the embed directive at the top of `validator.go`

### X-Tyk Extensions Not Working
**Problem:** X-Tyk extensions are not being validated.

**Solutions:**
- Check that `GetDefinitionsKey()` correctly detects the schema's definitions key
- Verify that `x-tyk-api-gateway.json` uses the correct definitions key
- Add debug logging to `loadOASSchema()` to see which key is being used

### Tests Failing
**Problem:** Existing tests fail after adding new schema.

**Solutions:**
- Check if `Test_setDefaultVersion` needs updating (it may expect a specific default)
- Verify that the new schema doesn't conflict with existing schemas
- Run tests in verbose mode to see detailed error messages: `go test -v`

## References

- [OpenAPI Specification](https://spec.openapis.org/)
- [JSON Schema Specification](https://json-schema.org/)
- [Tyk OAS Documentation](https://tyk.io/docs/getting-started/using-oas-definitions/)

## Contributing

When adding a new OAS version:
1. Follow this guide
2. Ensure all tests pass
3. Update this README if you discover any missing steps
4. Submit a PR with clear description of changes
