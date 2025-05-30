package reflect

import (
	"encoding/json"
	"math"
	"reflect"
)

// IsEmpty checks whether a field should be set to empty and omitted from OAS JSON.
func IsEmpty(i interface{}) bool {
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
		if v.IsNil() {
			return true
		}
		if v.Elem().Kind() == reflect.Bool {
			return false
		}

		return IsZero(v.Elem())
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

// Cast converts a value of type any to a specified type T.
// It does this by first marshaling the source value to JSON,
// and then unmarshaling the JSON byte slice into the destination type T.
//
// This function can be useful when dealing with dynamic or untyped data,
// such as data obtained from external sources or user input.
//
// The function returns a pointer to the converted value of type *T,
// and an error value if the conversion fails.
//
// Example:
//
//	type Person struct {
//		Name string
//		Age  int
//	}
//
//	data := map[string]any{
//		"Name": "Alice",
//		"Age":  30,
//	}
//
//	var p Person
//	pptr, err := Cast[Person](data)
//	if err != nil {
//		// Handle error
//	}
//	p = *pptr
//
// Note: The Cast function assumes that the source value can be marshaled
// and unmarshaled as JSON. If the source value contains types or values
// that cannot be represented in JSON, the function will return an error.
func Cast[T any](src any) (*T, error) {
	var dst T
	b, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, &dst)
	if err != nil {
		return nil, err
	}
	return &dst, nil
}
