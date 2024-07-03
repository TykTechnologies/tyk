package reflect

import (
	"go/ast"
	"reflect"
)

// TraverseAndReplace traverses any object and invokes a specified function on string fields.
// If a replacement has been made, it updates the values in the object with the new ones.
func TraverseAndReplace(obj interface{}, replaceFunc func(string) (string, bool)) {
	v := reflect.ValueOf(obj)

	if v.Kind() != reflect.Ptr || v.IsNil() {
		return
	}

	v = v.Elem()

	switch v.Kind() {
	case reflect.String:
		if v.CanSet() && v.CanAddr() {
			oldValue := v.String()
			newValue, replaced := replaceFunc(oldValue)
			if replaced {
				v.SetString(newValue)
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := v.Type().Field(i)

			if ast.IsExported(fieldType.Name) {
				TraverseAndReplace(field.Addr().Interface(), replaceFunc)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			TraverseAndReplace(elem.Addr().Interface(), replaceFunc)
		}
	}
}
