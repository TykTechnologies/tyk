package oas

import (
	"encoding/json"
	"math"
	"reflect"
)

// ShouldOmit checks whether a field should be set to empty and omitted from OAS JSON.
func ShouldOmit(i interface{}) bool {
	return IsZero(reflect.ValueOf(i))
}

// IsZero is a customized implementation of reflect.Value.IsZero. The built-in function accepts slice, map and pointer fields
// having 0 length as not zero. In OAS, we would like them to be counted as empty so we separated slice, map and pointer to
// different cases.
func IsZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return math.Float64bits(v.Float()) == 0
	case reflect.Complex64, reflect.Complex128:
		c := v.Complex()
		return math.Float64bits(real(c)) == 0 && math.Float64bits(imag(c)) == 0
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !IsZero(v.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		return v.IsNil()
	case reflect.Ptr:
		return v.IsNil() || IsZero(v.Elem())
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.String:
		return v.Len() == 0
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !IsZero(v.Field(i)) {
				return false
			}
		}
		return true
	default:
		// This should never happens, but will act as a safeguard for
		// later, as a default value doesn't makes sense here.
		panic(&reflect.ValueError{Method: "oas.IsZero", Kind: v.Kind()})
	}
}

func toStructIfMap(input interface{}, val interface{}) bool {
	mapInput, ok := input.(map[string]interface{})
	if !ok {
		return false
	}

	inBytes, err := json.Marshal(mapInput)
	if err != nil {
		log.Debug("Map input couldn't be marshalled")
	}

	err = json.Unmarshal(inBytes, val)
	if err != nil {
		log.Debug("Unmarshalling to struct couldn't succeed")
	}

	return true
}
