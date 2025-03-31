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

//go:embed testdata/fixtures/*.yml
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

	// Filename holds the fixture filename for output.
	Filename string

	// Tests hold the individual migration test cases.
	Tests []FixtureTest `yaml:"tests"`
}

// Fixture represents a single migration test case.
type FixtureTest struct {
	// Desc is an optional message to attach to the fixture.
	Desc string `yaml:"desc"`

	// Source indicates the source definition type, either "apidef" (classic API) or "oas".
	// Defaults to "apidef" if not specified.
	Source string `yaml:"source"`

	// Input holds the source API definition's explicitly set fields.
	Input map[string]any `yaml:"input"`

	// Output holds the expected OAS API definition's explicitly set fields.
	Output map[string]any `yaml:"output"`

	// Ignores will skip values in source
	Ignores []FixtureIgnore `yaml:"ignores"`

	// Errors should be configured to assert on errors.
	Errors FixtureError `yaml:"errors"`

	// Debug is used to print the resulting API values after api migration.
	Debug bool `yaml:"debug"`
}

// FixtureIgnore
type FixtureIgnore struct {
	// Key is a key to ignore. Supports a wildcard.
	Key string `yaml:"key"`

	// Values is a list of values to ignore.
	Values []any `yaml:"values"`
}

// FixtureError holds configuration for assertion errors in FixtureTest.
type FixtureError struct {
	// Desc is an optional message to attach to the error config.
	Desc string `yaml:"desc"`

	// Enabled if set to true will check error returns.
	Enabled bool `yaml:"enabled"`

	// Want if set to true will expect a filled error.
	Want bool `yaml:"want"`
}

// Fixtures will read the fixtures under fixtures/*.yml into a single
// document. Fixtures are appended together and order is not guaranteed.
func Fixtures(tb testing.TB) *FixtureDocument {
	doc := &FixtureDocument{}

	// Read all embedded fixture files matching testdata/fixtures/*.yml.
	files, err := fixtures.ReadDir("testdata/fixtures")
	assert.NoError(tb, err, "failed to read fixtures directory from embed FS")

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}

		data, err := fixtures.ReadFile("testdata/fixtures/" + file.Name())
		assert.NoError(tb, err, "failed to read "+file.Name()+" from embed FS")

		var f Fixture
		err = yaml.Unmarshal(data, &f)
		assert.NoError(tb, err, "failed to unmarshal "+file.Name()+" YAML")

		f.Filename = file.Name()

		// Append fixtures together
		doc.Fixtures = append(doc.Fixtures, f)
	}

	return doc
}

var encodeJSON = func(tb testing.TB, in any) []byte {
	tb.Helper()
	v, err := json.MarshalIndent(in, "", "  ")
	assert.NoError(tb, err)
	return v
}

func createOAS(tb testing.TB, patch any) *oas.OAS {
	tb.Helper()

	var def = &oas.OAS{
		T: openapi3.T{
			Info: &openapi3.Info{},
		},
	}

	if patch != nil {
		assert.NoError(tb, json.Unmarshal(encodeJSON(tb, patch), &def))
	}

	return def
}

func createClassic(tb testing.TB, patch any) *apidef.APIDefinition {
	tb.Helper()

	var def = &apidef.APIDefinition{
		VersionData: apidef.VersionData{
			Versions: map[string]apidef.VersionInfo{
				"v1": {
					GlobalSizeLimit:         0,
					GlobalSizeLimitDisabled: false,
				},
			},
		},
	}

	if patch != nil {
		assert.NoError(tb, json.Unmarshal(encodeJSON(tb, patch), &def))
	}

	def.Migrate()

	return def
}

func migrateClassic(def *apidef.APIDefinition) (*oas.OAS, error) {
	src := &oas.OAS{T: openapi3.T{Info: &openapi3.Info{}}}
	_, err := oas.FillOASFromClassicAPIDefinition(def, src)
	return src, err
}

func migrateOAS(def *oas.OAS) (*apidef.APIDefinition, error) {
	src := &apidef.APIDefinition{}
	def.ExtractTo(src)
	return src, nil
}

func flatMap(tb testing.TB, src any, base map[string]any) map[string]any {
	result := map[string]any{}
	err := json.Unmarshal(encodeJSON(tb, src), &result)
	assert.NoError(tb, err)

	result, err = Flatten(result)
	assert.NoError(tb, err)

	for k, v := range base {
		if vv, ok := result[k]; ok && strval(vv) == strval(v) {
			delete(result, k)
		}
	}

	return result
}

// TestFixtures loads the fixtures configuration from the embedded fixtures.yml,
// unmarshals the YAML content into a FixtureDocument, and logs the parsed fixtures.
// This test currently only prints the YAML content for debugging purposes.
func TestFixtures(t *testing.T) {
	doc := Fixtures(t)

	// Base migration gives us an initial state.
	oasEmpty := createOAS(t, nil)
	oasEmptyClassic, _ := migrateOAS(oasEmpty)
	oasEmptyMap := flatMap(t, oasEmptyClassic, nil)

	classicEmpty := createClassic(t, nil)
	classicEmptyOAS, _ := migrateClassic(classicEmpty)
	classicEmptyMap := flatMap(t, classicEmptyOAS, nil)

	// Optionally, iterate through each fixture and log its details.
	for _, fixture := range doc.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			for idx, tc := range fixture.Tests {
				t.Run(fmt.Sprintf("%s/%d", fixture.Filename, idx), func(t *testing.T) {
					var (
						err    error
						skip   map[string]any
						result map[string]any
					)

					switch tc.Source {
					case "oas":
						var dest *apidef.APIDefinition
						def := createOAS(t, tc.Input)

						dest, err = migrateOAS(def)

						assert.False(t, tc.Errors.Enabled, "OAS migrations to classic don't support error=true")

						if len(tc.Output) == 0 && !tc.Debug {
							skip = oasEmptyMap
						}
						result = flatMap(t, dest, skip)
					default:
						var dest *oas.OAS
						def := createClassic(t, tc.Input)

						dest, err = migrateClassic(def)

						if len(tc.Output) == 0 && !tc.Debug {
							skip = classicEmptyMap
						}
						result = flatMap(t, dest, skip)
					}

					if tc.Errors.Enabled {
						if tc.Debug {
							t.Logf("Checking errors enabled, %#v", tc.Errors)
						}
						if tc.Errors.Want {
							assert.Error(t, err)
						} else {
							assert.NoError(t, err)
						}
					}

					// Print Verbose output
					if tc.Debug || len(tc.Output) == 0 {
						keys := slices.Sorted(maps.Keys(result))

						t.Log("Changed keys after migration:")
						for _, k := range keys {
							raw := result[k]
							v := strval(raw)

							shouldIgnore := func() bool {
								for _, ign := range tc.Ignores {
									var matchedValue bool

									for _, ignval := range ign.Values {
										if v == strval(ignval) {
											matchedValue = true
											break
										}
									}

									matchedKey := ign.Key == "" || strings.Contains(k, ign.Key)

									if matchedKey && matchedValue {
										return true
									}
								}
								return false
							}()

							if shouldIgnore {
								continue
							}

							t.Logf("- %s \"%s\"", k, v)
						}
					}

					// Flatten expected output
					want := map[string]any{}
					if len(tc.Output) > 0 {
						want, err = Flatten(tc.Output)
						assert.NoError(t, err)
					} else {
						assert.True(t, tc.Debug, "Expecting configured `output` for test assertion.")
					}

					// Assert results
					for k, v := range want {
						got, ok := result[k]

						// If a key is not found, a "<nil>" value is matched against.
						// This allows the fixture to assert that a key doesn't exist.
						if got == nil {
							got = "<nil>"
							ok = true
						}

						if strval(v) == "<nil>" {
							// Check for nested flattened keys.
							for i, j := range result {
								assert.False(t, strings.HasPrefix(i, k+"."), "wanted %s=<nil>, found key %s=\"%v\"", k, i, j)
							}
						}

						assert.True(t, ok, "expected key %s in output", k)
						assert.Equal(t, v, got, "expected key %s=\"%v\", got \"%v\"", k, want, got)
					}
				})
			}
		})
	}
}

func strval(in any) string {
	return fmt.Sprintf("%v", in)
}
