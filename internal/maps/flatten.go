package maps

import (
	"fmt"
	"reflect"
)

// FlatMap is alias of map[string]string.
type FlatMap map[string]string

// Flatten transforms deep map to flat map.
func Flatten(data map[string]interface{}) (flatmap FlatMap, err error) {
	flatmap = make(FlatMap)
	for k, raw := range data {
		err = flatten(flatmap, k, reflect.ValueOf(raw))
		if err != nil {
			return nil, err
		}
	}
	return
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
	case reflect.Float64, reflect.Float32:
		result[prefix] = fmt.Sprintf("%f", v.Float())
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
	case reflect.Invalid:
		result[prefix] = ""
	default:
		return fmt.Errorf("Unknown: %s", v)
	}
	return nil
}

func flattenMap(result FlatMap, prefix string, v reflect.Value) (err error) {
	for _, k := range v.MapKeys() {
		if k.Kind() == reflect.Interface {
			k = k.Elem()
		}
		if k.Kind() != reflect.String {
			panic(fmt.Sprintf("%s: map key is not string: %s", prefix, k))
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
