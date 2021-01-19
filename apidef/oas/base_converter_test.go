package oas

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

func TestConverter_TykAPIDefinitionToSwagger(t *testing.T) {
	initialAPI := apidef.APIDefinition{}
	Fill(t, &initialAPI, 0)

	c := Converter{}
	s := openapi3.Swagger{}
	c.TykAPIDefinitionToSwagger(initialAPI, &s, "Default")
	convertedAPI := c.SwaggerToTykAPIDefinition(s, "Default")

	assert.Equal(t, initialAPI, convertedAPI)

	//bytes, _ := json.MarshalIndent(a, "", "  ")
	//fmt.Println(string(bytes))
}

func TestConverter_SwaggerToTykAPIDefinition(t *testing.T) {
	initialSwagger := openapi3.Swagger{}
	Fill(t, &initialSwagger, 0)


	//assert.Equal(t, api, a)

	bytes, _ := json.MarshalIndent(initialSwagger, "", "  ")
	fmt.Println(string(bytes))
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
		newMap := reflect.MakeMapWithSize(v.Type(), 0)

		for i := 0; i < 3; i++ {
			newKey := reflect.New(v.Type().Key()).Elem()
			Fill(t, newKey.Addr().Interface(), index+i)

			newValue := reflect.New(v.Type().Elem()).Elem()
			Fill(t, newValue.Addr().Interface(), index+i)

			newMap.SetMapIndex(newKey, newValue)
		}

		v.Set(newMap)

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fv := v.Field(i)
			if v.Type().Field(i).Tag.Get("json") == "-" || v.Type().Field(i).Tag.Get("json") == "" {
				continue
			}

			Fill(t, fv.Addr().Interface(), index+i+1)
		}

	case reflect.Ptr:
		newValue := reflect.New(v.Type().Elem()).Elem()
		Fill(t, newValue.Addr().Interface(), index)
		v.Set(newValue.Addr())
	default:
		t.Fatalf("uncovered kind in API definition: %s", kind.String())
	}
}
