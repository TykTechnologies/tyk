package reflect

import (
	"fmt"
	"reflect"
)

// FlatMap is alias of map[string]string
type FlatMap map[string]string

// Flatten transform complex map to flatten map
func Flatten(data map[string]interface{}) (FlatMap, error) {
	flatmap := make(FlatMap)
	for k, raw := range data {
		if err := flatten(flatmap, k, reflect.ValueOf(raw)); err != nil {
			return nil, err
		}
	}
	return flatmap, nil
}

func flatten(result FlatMap, prefix string, v reflect.Value) (err error) {
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			result[prefix] = "true"
		} else {
			result[prefix] = "false"
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		result[prefix] = fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		result[prefix] = fmt.Sprintf("%d", v.Uint())
	case reflect.Float64, reflect.Float32:
		result[prefix] = fmt.Sprintf("%f", v.Float())
	case reflect.Complex64, reflect.Complex128:
		result[prefix] = fmt.Sprint(v.Complex())
	case reflect.Map:
		err = flattenMap(result, prefix, v)
		if err != nil {
			return err
		}
	case reflect.Slice, reflect.Array:
		err = flattenSliceArray(result, prefix, v)
		if err != nil {
			return err
		}
	case reflect.Struct:
		err = flattenStruct(result, prefix, v)
		if err != nil {
			return err
		}
	case reflect.String:
		result[prefix] = v.String()
	case reflect.Invalid, reflect.Chan, reflect.Func, reflect.Interface, reflect.Pointer, reflect.UnsafePointer:
		return nil
	}
	return nil
}

func flattenMap(result FlatMap, prefix string, v reflect.Value) (err error) {
	for _, k := range v.MapKeys() {
		if k.Kind() != reflect.String {
			return fmt.Errorf("%s: map key is not string: %s", prefix, k)
		}
		err = flatten(result, fmt.Sprintf("%s.%s", prefix, k.String()), v.MapIndex(k))
		if err != nil {
			return err
		}
	}
	return nil
}

func flattenSliceArray(result FlatMap, prefix string, v reflect.Value) (err error) {
	prefix = prefix + "."
	for i := 0; i < v.Len(); i++ {
		err = flatten(result, fmt.Sprintf("%s%d", prefix, i), v.Index(i))
		if err != nil {
			return err
		}
	}
	return nil
}

func flattenStruct(result FlatMap, prefix string, v reflect.Value) (err error) {
	prefix = prefix + "."
	ty := v.Type()
	for i := 0; i < ty.NumField(); i++ {
		err = flatten(result, fmt.Sprintf("%s%s", prefix, ty.Field(i).Name), v.Field(i))
		if err != nil {
			return err
		}
	}
	return nil
}
