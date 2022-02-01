package jsonpointer

import (
	"reflect"
)

// JSONContainer returns any existing child value for a given JSON property string
type JSONContainer interface {
	// JSONProp takes a string reference for a given JSON property.
	// implementations must return any matching property of that name,
	// nil if no such subproperty exists.
	// Note that implementations on slice-types are expected to convert
	// prop to an integer value
	JSONProp(prop string) interface{}
}

// JSONParent is an interface that enables tree traversal by listing
// all immediate children of an object
type JSONParent interface {
	// JSONChildren should return all immidiate children of this element
	// with json property names as keys, go types as values
	// Note that implementations on slice-types are expected to convert
	// integers to string keys
	JSONProps() map[string]interface{}
}

// WalkJSON calls visit on all elements in a tree of decoded json
func WalkJSON(tree interface{}, visit func(elem interface{}) error) error {
	if tree == nil {
		return nil
	}

	if err := visit(tree); err != nil {
		return err
	}

	if con, ok := tree.(JSONParent); ok {
		for _, ch := range con.JSONProps() {
			if err := WalkJSON(ch, visit); err != nil {
				return err
			}
		}
		return nil
	}

	// fast-path for common json types
	switch t := tree.(type) {
	case map[string]interface{}:
		for _, val := range t {
			if err := WalkJSON(val, visit); err != nil {
				return err
			}
		}
		return nil
	case []interface{}:
		for _, val := range t {
			if err := WalkJSON(val, visit); err != nil {
				return err
			}
		}
		return nil
	}

	return walkValue(reflect.ValueOf(tree), visit)
}

func walkValue(v reflect.Value, visit func(elem interface{}) error) error {
	switch v.Kind() {
	case reflect.Invalid:
		return nil
	case reflect.Ptr:
		if !v.IsNil() {
			walkValue(v.Elem(), visit)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			mi := v.MapIndex(key)
			if mi.CanInterface() {
				WalkJSON(mi.Interface(), visit)
			}
		}
	case reflect.Struct:
		// t := v.Type()
		// TypeOf returns the reflection Type that represents the dynamic type of variable.
		// If variable is a nil interface value, TypeOf returns nil.
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			// fmt.Printf("%d: %s %s %s = %v\n", i, t.Field(i).Name, f.Type(), t.Field(i).Tag.Get("json"), f.CanInterface())
			if f.CanInterface() {
				WalkJSON(f.Interface(), visit)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			WalkJSON(v.Index(i).Interface(), visit)
		}
	}
	return nil
}
