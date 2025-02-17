package oas_test

import (
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/reflect"
)

var Flatten = reflect.Flatten

// The fixtures.yml file contains a list of migration areas and corresponding test cases,
// each with a source API definition ("apidef" by default) and its expected OAS migration output.
//
// Example fixtures.yml:
//
//   fixtures:
//   - name: ServiceDefinition migrations
//     tests:
//       - input:
//           proxy:
//             service_discovery:
//               use_discovery_service: true
//               cache_disabled: false
//               cache_timeout: 10
//         output:
//           upstream:
//             serviceDiscovery:
//               enabled: false
//

//go:embed fixtures/*.yml
var fixtures embed.FS

// FixtureDocument represents the root structure of the fixtures configuration.
// It contains a collection of migration fixtures.
type FixtureDocument struct {
	Fixtures []Fixture
}

// Fixture represents a single migration test case.
// It defines a conversion between a classic API definition and its expected OAS migration output.
type Fixture struct {
	// Name holds the name of the fixture, e.g. a product area, a feature.
	Name string

	// Tests hold the individual migration test cases.
	Tests []FixtureTest `yaml:"tests"`
}

// Fixture represents a single migration test case.
type FixtureTest struct {
	// Variant is an optional message to attach to the fixture.
	Variant string `yaml:"variant"`

	// Source indicates the source definition type, either "apidef" (classic API) or "oas".
	// Defaults to "apidef" if not specified.
	Source string `yaml:"source"`

	// Input holds the source API definition's explicitly set fields.
	Input map[string]any `yaml:"input"`

	// Output holds the expected OAS API definition's explicitly set fields.
	Output map[string]any `yaml:"output"`
}

// Fixtures will read the fixtures under fixtures/*.yml into a single
// document. Fixtures are appended together and order is not guaranteed.
func Fixtures(tb testing.TB) *FixtureDocument {
	doc := &FixtureDocument{}

	// Read all embedded fixture files matching fixtures/*.yml.
	files, err := fixtures.ReadDir("fixtures")
	assert.NoError(tb, err, "failed to read fixtures directory from embed FS")

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}

		data, err := fixtures.ReadFile("fixtures/" + file.Name())
		assert.NoError(tb, err, "failed to read "+file.Name()+" from embed FS")

		var f Fixture
		err = yaml.Unmarshal(data, &f)
		assert.NoError(tb, err, "failed to unmarshal "+file.Name()+" YAML")

		// Append fixtures together
		doc.Fixtures = append(doc.Fixtures, f)
	}

	return doc
}

// TestFixtures loads the fixtures configuration from the embedded fixtures.yml,
// unmarshals the YAML content into a FixtureDocument, and logs the parsed fixtures.
// This test currently only prints the YAML content for debugging purposes.
func TestFixtures(t *testing.T) {
	encodeJSON := func(in any) []byte {
		v, err := json.MarshalIndent(in, "", "  ")
		assert.NoError(t, err)
		return v
	}

	doc := Fixtures(t)

	// Optionally, iterate through each fixture and log its details.
	for _, fixture := range doc.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			for idx, tc := range fixture.Tests {
				name := tc.Variant
				if name == "" {
					name = fmt.Sprintf("case %d", idx)
				}
				t.Run(name, func(t *testing.T) {
					var oasMap = make(map[string]any)

					switch tc.Source {
					case "oas":
						// Read in input api definition
						var from *oas.OAS = &oas.OAS{T: openapi3.T{}}
						assert.NoError(t, json.Unmarshal(encodeJSON(tc.Input), &from))

						// Fill oas from api definition, src modified in place.
						src := &apidef.APIDefinition{}
						from.ExtractTo(src)
						oasJSON := encodeJSON(src)

						assert.NoError(t, json.Unmarshal(oasJSON, &oasMap))

						// Flatten output
						oasFlatMap, err := Flatten(oasMap)
						assert.NoError(t, err)

						// Print debug output
						if false {
							keys := slices.Sorted(maps.Keys(oasFlatMap))

							for _, k := range keys {
								v := oasFlatMap[k]
								t.Log("-", k, v)
							}
						}

						// Flatten expected output
						outputFlatMap, err := Flatten(tc.Output)
						assert.NoError(t, err)

						// Assert results
						for k, want := range outputFlatMap {
							got, ok := oasFlatMap[k]

							assert.True(t, ok, "expected key %s in output", k)
							assert.Equal(t, want, got, "expected key %s=%s, got %s", k, want, got)
						}
					default:
						// Read in input api definition
						var from apidef.APIDefinition
						assert.NoError(t, json.Unmarshal(encodeJSON(tc.Input), &from))
						from.Migrate()

						// Fill oas from api definition, src modified in place.
						src := &oas.OAS{T: openapi3.T{}}
						oas.FillOASFromClassicAPIDefinition(&from, src)
						oasJSON := encodeJSON(src)

						assert.NoError(t, json.Unmarshal(oasJSON, &oasMap))

						// Flatten output
						oasFlatMap, err := Flatten(oasMap)
						assert.NoError(t, err)

						// Print debug output
						if false {
							keys := slices.Sorted(maps.Keys(oasFlatMap))

							for _, k := range keys {
								v := oasFlatMap[k]
								t.Log("-", k, v)
							}
						}

						// Flatten expected output
						outputFlatMap, err := Flatten(tc.Output)
						assert.NoError(t, err)

						// Assert results
						for k, want := range outputFlatMap {
							got, ok := oasFlatMap[k]

							assert.True(t, ok, "expected key %s in output", k)
							assert.Equal(t, want, got, "expected key %s=%s, got %s", k, want, got)
						}
					}
				})
			}
		})
	}
}
