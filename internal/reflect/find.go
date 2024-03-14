package reflect

import (
	"go/ast"
	"reflect"
)

// TraverseAndFind traverses any object and invokes a specified function on string fields.
// If the function returns true, the value will be returned in the result.
func TraverseAndFind(obj interface{}, findFunc func(string) bool) []string {
	var results []string

	v := reflect.ValueOf(obj)

	if v.Kind() != reflect.Ptr || v.IsNil() {
		return results
	}

	v = v.Elem()

	switch v.Kind() {
	case reflect.String:
		if v.CanSet() && v.CanAddr() {
			value := v.String()
			found := findFunc(value)
			if found {
				results = append(results, value)
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := v.Type().Field(i)

			if ast.IsExported(fieldType.Name) {
				results = append(results, TraverseAndFind(field.Addr().Interface(), findFunc)...)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			results = append(results, TraverseAndFind(elem.Addr().Interface(), findFunc)...)
		}
	}

	return results
}
