package reflect

import (
	"fmt"
	"reflect"
)

// FlatMap is alias of map[string]any.
type FlatMap map[string]any

// Flatten transforms deep map to flat map.
// The numeric types are coalesced to float64.
func Flatten(data map[string]any) (flatmap FlatMap, err error) {
	flatmap = make(FlatMap)
	for k, raw := range data {
		err = flatten(flatmap, k, reflect.ValueOf(raw))
		if err != nil {
			return nil, err
		}
	}
	return
}

// unlike maps.Flatten, this flatten coalesces numeric types to a float64 value.
// this is used in yaml decoding to map[]any as a numeric type.
func flatten(result FlatMap, prefix string, v reflect.Value) (err error) {
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Bool:
		result[prefix] = v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanInt() {
			result[prefix] = float64(v.Int())
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanUint() {
			result[prefix] = float64(v.Uint())
		}
	case reflect.Float64, reflect.Float32:
		if v.CanFloat() {
			result[prefix] = v.Float()
		}
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
