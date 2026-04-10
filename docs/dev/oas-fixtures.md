# OAS Fixtures

A test fixture is a device used to consistently test some item, device, or piece of software.

It's a common concern to answer the following questions:

- What is the definition of an OAS feature like UptimeTests
- What are the classic API fields that contract is being migrated to
- Are classic settings migrated to OAS definitions correctly (reverse test)

The fixtures are located under `apidef/oas/testdata/fixtures`. Extend the location with new migration tests. Lets take a look at an example development flow.

In addition to running `task` in `apidef/oas`, you can use the fixtures test file to run only the fixtures, due to the black box nature of the test.

```bash
go test -count=1 -v fixtures_test.go
```

The tests are run and filled from fixture yaml files.

## Creating a fixture

When creating a fixture, create a `plugins.yml` or `service_discovery.yml` or similarly named files under apidef/oas fixtures. Start with either a classic API setting, or an OAS API setting, for example:

```yaml
---
name: "Plugins"
tests:
  - desc: "From OAS to Classic"
    source: oas
    debug: true
    input:
      x-tyk-api-gateway:
        server:
          authentication:
            custom:
              enabled: true
              functionName: "name"
              path: "/path/to/file.so"
              rawBodyOnly: true
              requireSession: true
```

- `source` can be `oas` or `classic`
- `debug` set to true will print which fields have been modified
- `input` declares api definition schema based on source
- `output` checks the migrated api definition for values

This fixture defines a test case that sets OAS inputs. By running the fixture tests, they detect this and print any changed values vs. the migration that would result with an empty input. The idea behind it is that each input field maps to one or more values between schemas.

If you don't configure `output` and set `debug=true`:

```text
=== RUN   TestFixtures/Plugins/From_OAS_to_Classic
    fixtures_test.go:280: Ignores: []
    fixtures_test.go:281: Changed keys after migration:
    fixtures_test.go:306: - custom_plugin_auth_enabled "true"
```

This gives you a way to fill out `output`.

```yaml
    output:
      custom_plugin_auth_enabled: true
```

For the migration example you can see that some fields have not been migrated (functionName, path, etc.). The list of detected results is untrimmed, assertions should be added and migration fixed.

## Additional fixture settings

Additional fixture settings are possible for asserting errors:

```yaml
    errors:
      enabled: true
      want: true
```

By default error checks are not enabled, and if you enable them then it should be set to `want: true` if an error is expected. Due to validation failing with API definition partials, it's suggested to leave this inconfigured.

## Debug output filtering

If you're looking at debug output and want to ignore keys or values, you can configure `ignores` to skip a combination of keys or values you set:

```yaml
    ignores:
      - key: "use_"
        values: [false]
      - key: "disabled"
        values: [true]
      - values: ["", 0]
```
