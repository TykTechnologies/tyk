package oas

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/TykTechnologies/kin-openapi/openapi3"

	"github.com/stretchr/testify/assert"

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

// Fill populates the given input with non-default values. Index is where to start incrementing values.
func Fill(t *testing.T, input interface{}, index int) {
	v := reflect.ValueOf(input).Elem()

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
				Fill(t, newValue.Addr().Interface(), index+i)
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
				Fill(t, newKey.Addr().Interface(), index+i)

				newValue := reflect.New(v.Type().Elem()).Elem()
				Fill(t, newValue.Addr().Interface(), index+i)

				newMap.SetMapIndex(newKey, newValue)
			}

			v.Set(newMap)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(apidef.VersionData{}) {
			v.Set(reflect.ValueOf(FillTestVersionData(t, index)))
		} else {
			for i := 0; i < v.NumField(); i++ {
				fv := v.Field(i)
				if v.Type().Field(i).Tag.Get("json") == "-" || v.Type().Field(i).Tag.Get("json") == "" {
					continue
				}

				Fill(t, fv.Addr().Interface(), index+i+1)
			}
		}
	case reflect.Ptr:
		newValue := reflect.New(v.Type().Elem()).Elem()
		Fill(t, newValue.Addr().Interface(), index)
		v.Set(newValue.Addr())
	default:
		t.Fatalf("uncovered kind in API definition: %s", kind.String())
	}
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

	var convertedAPI apidef.APIDefinition
	emptyVersioning.ExtractTo(&convertedAPI)

	var resultVersioning Versioning
	resultVersioning.Fill(convertedAPI)

	assert.Equal(t, emptyVersioning, resultVersioning)
}
