package oas

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestXTykAPIGateway(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyXTykAPIGateway XTykAPIGateway

		var convertedAPI apidef.APIDefinition
		emptyXTykAPIGateway.ExtractTo(&convertedAPI)

		var resultXTykAPIGateway XTykAPIGateway
		resultXTykAPIGateway.Fill(convertedAPI)

		assert.Equal(t, emptyXTykAPIGateway, resultXTykAPIGateway)
	})

	t.Run("filled OAS", func(t *testing.T) {
		t.SkipNow()
		var oas OAS
		Fill(t, &oas, 0)
		oas.Security = openapi3.SecurityRequirements{
			{
				"custom": []string{},
			},
		}

		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"custom": {
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						Name: "x-query",
						In:   "query",
					},
				},
			},
		}

		var xTykAPIGateway XTykAPIGateway
		Fill(t, &xTykAPIGateway, 0)
		xTykAPIGateway.Server.Authentication = &Authentication{
			SecuritySchemes: SecuritySchemes{
				"custome": &Token{},
			},
		}

		oas.Extensions = map[string]interface{}{
			ExtensionTykAPIGateway: &xTykAPIGateway,
		}

		var convertedAPI apidef.APIDefinition
		oas.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		assert.Equal(t, oas, resultOAS)
	})

	t.Run("filled old", func(t *testing.T) {
		t.SkipNow() // when we don't need to skip this, it means OAS and Tyk classic API definition match
		initialAPI := apidef.APIDefinition{}
		Fill(t, &initialAPI, 0)

		initialAPI.VersionDefinition.Enabled = false
		initialAPI.VersionDefinition.Versions = nil
		_, err := initialAPI.MigrateVersioning()
		assert.NoError(t, err)

		xTykAPIGateway := XTykAPIGateway{}
		xTykAPIGateway.Fill(initialAPI)

		ss, err := json.MarshalIndent(xTykAPIGateway, "", "  ")
		assert.NoError(t, err)

		t.Logf("JSON from filled old:\n%s", string(ss))

		var convertedAPI apidef.APIDefinition
		xTykAPIGateway.ExtractTo(&convertedAPI)

		assert.Equal(t, initialAPI, convertedAPI)
	})
}

func TestXTykAPIGateway_EnableContextVariables(t *testing.T) {
	t.Parallel()
	enabledExpectation := XTykAPIGateway{
		Middleware: &Middleware{
			Global: &Global{
				ContextVariables: &ContextVariables{
					Enabled: true,
				},
			},
		},
	}
	disabledExpectation := XTykAPIGateway{
		Middleware: &Middleware{
			Global: &Global{
				ContextVariables: &ContextVariables{
					Enabled: false,
				},
			},
		},
	}
	testCases := []struct {
		name   string
		in     XTykAPIGateway
		expect XTykAPIGateway
	}{
		{
			name:   "empty XTykAPIGateway",
			in:     XTykAPIGateway{},
			expect: enabledExpectation,
		},
		{
			name: "empty XTykAPIGateway.Middleware",
			in: XTykAPIGateway{
				Middleware: &Middleware{},
			},
			expect: enabledExpectation,
		},
		{
			name: "empty XTykAPIGateway.Middleware.Global",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{},
				},
			},
			expect: enabledExpectation,
		},
		{
			name: "empty XTykAPIGateway.Middleware.Global.ContextVariables",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{
						ContextVariables: &ContextVariables{},
					},
				},
			},
			expect: disabledExpectation,
		},
		{
			name: "enabled XTykAPIGateway.Middleware.Global.ContextVariables",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{
						ContextVariables: &ContextVariables{
							Enabled: true,
						},
					},
				},
			},
			expect: enabledExpectation,
		},
		{
			name: "disabled XTykAPIGateway.Middleware.Global.ContextVariables",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{
						ContextVariables: &ContextVariables{
							Enabled: false,
						},
					},
				},
			},
			expect: disabledExpectation,
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.in.enableContextVariablesIfEmpty()
			assert.EqualExportedValues(t, tc.expect, tc.in)
		})
	}
}

func TestInfo(t *testing.T) {
	var emptyInfo Info

	var convertedAPI apidef.APIDefinition
	emptyInfo.ExtractTo(&convertedAPI)

	var resultInfo Info
	resultInfo.Fill(convertedAPI)

	assert.Equal(t, emptyInfo, resultInfo)
}

func TestState(t *testing.T) {
	var emptyState State

	var convertedAPI apidef.APIDefinition
	emptyState.ExtractTo(&convertedAPI)

	var resultState State
	resultState.Fill(convertedAPI)

	assert.Equal(t, emptyState, resultState)
}

type FillContext string

const (
	FillContextOAS FillContext = "oas"
	FillContextMCP FillContext = "mcp"
)

var mcpOnlyFields = map[string]bool{
	"McpTools":     true,
	"McpResources": true,
	"McpPrompts":   true,
}

func FillWithContext(t *testing.T, input interface{}, index int, ctx FillContext) {
	t.Helper()
	fillValue(reflect.ValueOf(input).Elem(), index, ctx, t)
}

func Fill(t *testing.T, input interface{}, index int) {
	t.Helper()
	FillWithContext(t, input, index, FillContextMCP)
}

func fillValue(v reflect.Value, index int, ctx FillContext, t *testing.T) {

	switch kind := v.Type().Kind(); kind {
	case reflect.String:
		v.SetString(fmt.Sprintf("%d", index))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(index))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(index))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(index))
	case reflect.Slice:
		if v.Type() == reflect.TypeOf(json.RawMessage{}) {
			v.Set(reflect.ValueOf(json.RawMessage(`{"test-key":"test-value"}`)))
		} else {
			newSlice := reflect.MakeSlice(v.Type(), 3, 3)

			for i := 0; i < 3; i++ {
				newValue := reflect.New(v.Type().Elem()).Elem()
				fillValue(newValue, index+i, ctx, t)
				newSlice.Index(i).Set(newValue)
			}

			v.Set(newSlice)
		}
	case reflect.Interface:
		v.Set(reflect.ValueOf(1))
	case reflect.Map:

		if v.Type() == reflect.TypeOf(map[string]apidef.AuthConfig{}) {
			v.Set(reflect.ValueOf(FillTestAuthConfigs(t, index)))
		} else {
			newMap := reflect.MakeMapWithSize(v.Type(), 0)
			for i := 0; i < 3; i++ {
				newKey := reflect.New(v.Type().Key()).Elem()
				fillValue(newKey, index+i, ctx, t)

				newValue := reflect.New(v.Type().Elem()).Elem()
				fillValue(newValue, index+i, ctx, t)

				newMap.SetMapIndex(newKey, newValue)
			}

			v.Set(newMap)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(apidef.VersionData{}) {
			v.Set(reflect.ValueOf(FillTestVersionData(t, index)))
		} else {
			for i := 0; i < v.NumField(); i++ {
				field := v.Type().Field(i)
				fv := v.Field(i)
				if field.Tag.Get("json") == "-" || field.Tag.Get("json") == "" {
					continue
				}

				if shouldSkipField(field, ctx) {
					continue
				}

				fillValue(fv, index+i+1, ctx, t)
			}
		}
	case reflect.Ptr:
		newValue := reflect.New(v.Type().Elem()).Elem()
		fillValue(newValue, index, ctx, t)
		v.Set(newValue.Addr())
	default:
		t.Fatalf("uncovered kind in API definition: %s", kind.String())
	}
}

func shouldSkipField(field reflect.StructField, ctx FillContext) bool {
	if ctx == FillContextOAS && mcpOnlyFields[field.Name] {
		return true
	}
	return false
}

// getNonEmptyFields returns non-empty fields inside a struct.
func getNonEmptyFields(data interface{}, prefix string) (fields []string) {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Struct {
		fields = append(fields, prefix)
		return
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := val.Type().Field(i)

		fieldName := fieldType.Name
		fullName := prefix + "." + fieldName

		switch field.Kind() {
		case reflect.String:
			if field.String() != "" {
				fields = append(fields, fullName)
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if field.Int() != 0 {
				fields = append(fields, fullName)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if field.Uint() != 0 {
				fields = append(fields, fullName)
			}
		case reflect.Float32, reflect.Float64:
			if field.Float() != 0 {
				fields = append(fields, fullName)
			}
		case reflect.Bool:
			if field.Bool() {
				fields = append(fields, fullName)
			}
		case reflect.Struct:
			fields = append(fields, getNonEmptyFields(field.Interface(), fullName)...)
		case reflect.Array, reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				elemFullName := fullName + fmt.Sprintf("[%d]", j)
				fields = append(fields, getNonEmptyFields(field.Index(j).Interface(), elemFullName)...)
				break
			}

		case reflect.Map:
			for _, key := range field.MapKeys() {
				elemFullName := fullName + "[0]"
				fields = append(fields, getNonEmptyFields(field.MapIndex(key).Interface(), elemFullName)...)
				break
			}
		case reflect.Interface:
			if !field.IsNil() {
				fields = append(fields, getNonEmptyFields(field.Elem().Interface(), fullName)...)
			}
		case reflect.Ptr:
			if !field.IsNil() {
				fields = append(fields, getNonEmptyFields(field.Elem().Interface(), fullName)...)
			}
		default:
			panic(fmt.Sprintf("unsupported kind: %v", field.Kind()))
		}

	}

	return fields
}

func FillTestAuthConfigs(t *testing.T, index int) map[string]apidef.AuthConfig {
	t.Helper()
	authConfigs := make(map[string]apidef.AuthConfig)

	a := apidef.AuthConfig{}
	Fill(t, &a, index)
	authConfigs["authToken"] = a

	a.UseCertificate = false
	a.Signature = apidef.SignatureConfig{}
	a.ValidateSignature = false
	authConfigs["jwt"] = a
	authConfigs["basic"] = a
	authConfigs["oauth"] = a
	authConfigs["hmac"] = a
	authConfigs["coprocess"] = a
	authConfigs["oidc"] = a

	return authConfigs
}

func FillTestVersionData(t *testing.T, index int) apidef.VersionData {
	t.Helper()
	versionInfo := apidef.VersionInfo{}
	Fill(t, &versionInfo, index)

	return apidef.VersionData{
		NotVersioned:   false,
		DefaultVersion: "Default",
		Versions: map[string]apidef.VersionInfo{
			"Default": versionInfo,
			"v1":      {},
			"v2":      {},
		},
	}
}

func TestVersioning(t *testing.T) {
	var emptyVersioning Versioning
	emptyVersioning.Versions = []VersionToID{}

	var convertedAPI apidef.APIDefinition
	emptyVersioning.ExtractTo(&convertedAPI)

	var resultVersioning Versioning
	resultVersioning.Fill(convertedAPI)

	assert.Equal(t, emptyVersioning, resultVersioning)
}

func TestXTykAPIGateway_enableTrafficLogsIfEmpty(t *testing.T) {
	t.Parallel()
	enabledExpectation := XTykAPIGateway{
		Middleware: &Middleware{
			Global: &Global{
				TrafficLogs: &TrafficLogs{
					Enabled: true,
				},
			},
		},
	}
	disabledExpectation := XTykAPIGateway{
		Middleware: &Middleware{
			Global: &Global{
				TrafficLogs: &TrafficLogs{
					Enabled: false,
				},
			},
		},
	}
	testCases := []struct {
		name   string
		in     XTykAPIGateway
		expect XTykAPIGateway
	}{
		{
			name:   "empty XTykAPIGateway",
			in:     XTykAPIGateway{},
			expect: enabledExpectation,
		},
		{
			name: "empty XTykAPIGateway.Middleware",
			in: XTykAPIGateway{
				Middleware: &Middleware{},
			},
			expect: enabledExpectation,
		},
		{
			name: "empty XTykAPIGateway.Middleware.Global",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{},
				},
			},
			expect: enabledExpectation,
		},
		{
			name: "empty XTykAPIGateway.Middleware.Global.TrafficLogs",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{
						TrafficLogs: &TrafficLogs{},
					},
				},
			},
			expect: disabledExpectation,
		},
		{
			name: "enabled XTykAPIGateway.Middleware.Global.TrafficLogs",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{
						TrafficLogs: &TrafficLogs{
							Enabled: true,
						},
					},
				},
			},
			expect: enabledExpectation,
		},
		{
			name: "disabled XTykAPIGateway.Middleware.Global.TrafficLogs",
			in: XTykAPIGateway{
				Middleware: &Middleware{
					Global: &Global{
						TrafficLogs: &TrafficLogs{
							Enabled: false,
						},
					},
				},
			},
			expect: disabledExpectation,
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.in.enableTrafficLogsIfEmpty()
			assert.EqualExportedValues(t, tc.expect, tc.in)
		})
	}
}
func TestFillWithContext(t *testing.T) {
	t.Run("FillContextMCP fills MCP fields", func(t *testing.T) {
		m := &Middleware{}
		FillWithContext(t, m, 0, FillContextMCP)

		assert.NotNil(t, m.McpTools)
		assert.NotNil(t, m.McpResources)
		assert.NotNil(t, m.McpPrompts)
		assert.NotNil(t, m.Global)
	})

	t.Run("FillContextOAS skips MCP fields", func(t *testing.T) {
		m := &Middleware{}
		FillWithContext(t, m, 0, FillContextOAS)

		assert.Nil(t, m.McpTools)
		assert.Nil(t, m.McpResources)
		assert.Nil(t, m.McpPrompts)
		assert.NotNil(t, m.Global)
	})

	t.Run("backward compatible Fill uses MCP context", func(t *testing.T) {
		m := &Middleware{}
		Fill(t, m, 0)

		assert.NotNil(t, m.McpTools)
		assert.NotNil(t, m.McpResources)
		assert.NotNil(t, m.McpPrompts)
		assert.NotNil(t, m.Global)
	})

	t.Run("nested structs respect context", func(t *testing.T) {
		gw := &XTykAPIGateway{}
		FillWithContext(t, gw, 0, FillContextOAS)

		assert.NotNil(t, gw.Middleware)
		assert.Nil(t, gw.Middleware.McpTools)
		assert.Nil(t, gw.Middleware.McpResources)
		assert.Nil(t, gw.Middleware.McpPrompts)
	})
}

func TestErrorOverrides_FillExtract(t *testing.T) {
	t.Run("fill and extract with error overrides enabled", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"404": []apidef.ErrorOverride{
					{
						Match: &apidef.ErrorMatcher{
							Flag:           "upstream_timeout",
							MessagePattern: "timeout.*",
							BodyField:      "error.code",
							BodyValue:      "TIMEOUT",
						},
						Response: apidef.ErrorResponse{
							StatusCode: 504,
							Message:    "Gateway Timeout",
							Body:       `{"error": "upstream unavailable"}`,
							Template:   "timeout.html",
							Headers:    map[string]string{"X-Custom": "timeout"},
						},
					},
				},
				"500": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 500,
							Template:   "error_500.tmpl",
							Body:       `{"error": "internal server error"}`,
						},
					},
				},
			},
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		assert.True(t, x.ErrorOverrides.Enabled)
		assert.NotNil(t, x.ErrorOverrides.Value)
		assert.Len(t, x.ErrorOverrides.Value, 2)
		assert.Len(t, x.ErrorOverrides.Value["404"], 1)

		override404 := x.ErrorOverrides.Value["404"][0]
		assert.Equal(t, 504, override404.Response.StatusCode)
		assert.Equal(t, "upstream_timeout", string(override404.Match.Flag))
		assert.Equal(t, "timeout.*", override404.Match.MessagePattern)
		assert.Equal(t, "error.code", override404.Match.BodyField)
		assert.Equal(t, "TIMEOUT", override404.Match.BodyValue)
		assert.Equal(t, "Gateway Timeout", override404.Response.Message)
		assert.Equal(t, `{"error": "upstream unavailable"}`, override404.Response.Body)
		assert.Equal(t, "timeout.html", override404.Response.Template)
		assert.Equal(t, "timeout", override404.Response.Headers["X-Custom"])

		override500 := x.ErrorOverrides.Value["500"][0]
		assert.Equal(t, 500, override500.Response.StatusCode)
		assert.Equal(t, "error_500.tmpl", override500.Response.Template)
		assert.Equal(t, `{"error": "internal server error"}`, override500.Response.Body)
		assert.Nil(t, override500.Match)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.False(t, extracted.ErrorOverridesDisabled)
		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
		assert.Equal(t, "timeout.*", extracted.ErrorOverrides["404"][0].Match.MessagePattern)
		assert.Equal(t, "error.code", extracted.ErrorOverrides["404"][0].Match.BodyField)
		assert.Equal(t, "TIMEOUT", extracted.ErrorOverrides["404"][0].Match.BodyValue)
	})

	t.Run("fill and extract with error overrides disabled", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: true,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"404": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 404,
							Body:       `{"error": "not found"}`,
						},
					},
				},
			},
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		assert.False(t, x.ErrorOverrides.Enabled)
		assert.NotNil(t, x.ErrorOverrides.Value)
		assert.Len(t, x.ErrorOverrides.Value, 1)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.True(t, extracted.ErrorOverridesDisabled)
		assert.NotNil(t, extracted.ErrorOverrides)
		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
	})

	t.Run("extract with nil error overrides", func(t *testing.T) {
		var x XTykAPIGateway
		x.ErrorOverrides = nil

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.True(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
	})

	t.Run("extract with error overrides but empty value", func(t *testing.T) {
		var x XTykAPIGateway
		x.ErrorOverrides = &ErrorOverrides{
			Enabled: true,
			Value:   nil,
		}

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.False(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
	})
}

func TestErrorOverrides_EmptyMap(t *testing.T) {
	t.Run("nil error overrides", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides:         nil,
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		assert.True(t, x.ErrorOverrides.Enabled)
		assert.Nil(t, x.ErrorOverrides.Value)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.False(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
	})

	t.Run("disabled with nil error overrides", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: true,
			ErrorOverrides:         nil,
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.Nil(t, x.ErrorOverrides)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.True(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
	})
}

func TestErrorOverrides_EdgeCases(t *testing.T) {
	t.Run("error override without match criteria", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Match: nil,
						Response: apidef.ErrorResponse{
							StatusCode: 401,
							Body:       `{"error": "unauthorized"}`,
							Message:    "Access denied",
							Headers:    map[string]string{"WWW-Authenticate": "Bearer"},
						},
					},
				},
			},
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		assert.True(t, x.ErrorOverrides.Enabled)
		require.Len(t, x.ErrorOverrides.Value["401"], 1)

		override := x.ErrorOverrides.Value["401"][0]
		assert.Nil(t, override.Match)
		assert.Equal(t, 401, override.Response.StatusCode)
		assert.Equal(t, "Access denied", override.Response.Message)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.False(t, extracted.ErrorOverridesDisabled)
		require.Len(t, extracted.ErrorOverrides["401"], 1)
		assert.Nil(t, extracted.ErrorOverrides["401"][0].Match)
		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
	})

	t.Run("multiple overrides for same status code", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"500": []apidef.ErrorOverride{
					{
						Match: &apidef.ErrorMatcher{
							Flag: "database_error",
						},
						Response: apidef.ErrorResponse{
							StatusCode: 503,
							Body:       `{"error": "database unavailable"}`,
						},
					},
					{
						Match: &apidef.ErrorMatcher{
							Flag: "timeout_error",
						},
						Response: apidef.ErrorResponse{
							StatusCode: 504,
							Body:       `{"error": "request timeout"}`,
						},
					},
				},
			},
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		assert.True(t, x.ErrorOverrides.Enabled)
		require.Len(t, x.ErrorOverrides.Value["500"], 2)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.False(t, extracted.ErrorOverridesDisabled)
		require.Len(t, extracted.ErrorOverrides["500"], 2)
		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
	})

	t.Run("error response with empty headers", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"403": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 403,
							Body:       `{"error": "forbidden"}`,
							Headers:    map[string]string{},
						},
					},
				},
			},
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		require.Len(t, x.ErrorOverrides.Value["403"], 1)

		override := x.ErrorOverrides.Value["403"][0]
		assert.NotNil(t, override.Response.Headers)
		assert.Len(t, override.Response.Headers, 0)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
	})

	t.Run("error response with nil headers", func(t *testing.T) {
		api := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"502": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 502,
							Body:       `{"error": "bad gateway"}`,
							Headers:    nil,
						},
					},
				},
			},
		}

		var x XTykAPIGateway
		x.Fill(api)

		assert.NotNil(t, x.ErrorOverrides)
		require.Len(t, x.ErrorOverrides.Value["502"], 1)

		override := x.ErrorOverrides.Value["502"][0]
		assert.Nil(t, override.Response.Headers)

		var extracted apidef.APIDefinition
		x.ExtractTo(&extracted)

		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
	})
}
