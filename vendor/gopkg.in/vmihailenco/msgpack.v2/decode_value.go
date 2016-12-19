package msgpack

import (
	"fmt"
	"io/ioutil"
	"reflect"
)

var interfaceType = reflect.TypeOf((*interface{})(nil)).Elem()
var stringType = reflect.TypeOf((*string)(nil)).Elem()

var valueDecoders []decoderFunc

func init() {
	valueDecoders = []decoderFunc{
		reflect.Bool:          decodeBoolValue,
		reflect.Int:           decodeInt64Value,
		reflect.Int8:          decodeInt64Value,
		reflect.Int16:         decodeInt64Value,
		reflect.Int32:         decodeInt64Value,
		reflect.Int64:         decodeInt64Value,
		reflect.Uint:          decodeUint64Value,
		reflect.Uint8:         decodeUint64Value,
		reflect.Uint16:        decodeUint64Value,
		reflect.Uint32:        decodeUint64Value,
		reflect.Uint64:        decodeUint64Value,
		reflect.Float32:       decodeFloat32Value,
		reflect.Float64:       decodeFloat64Value,
		reflect.Complex64:     decodeUnsupportedValue,
		reflect.Complex128:    decodeUnsupportedValue,
		reflect.Array:         decodeArrayValue,
		reflect.Chan:          decodeUnsupportedValue,
		reflect.Func:          decodeUnsupportedValue,
		reflect.Interface:     decodeInterfaceValue,
		reflect.Map:           decodeMapValue,
		reflect.Ptr:           decodeUnsupportedValue,
		reflect.Slice:         decodeSliceValue,
		reflect.String:        decodeStringValue,
		reflect.Struct:        decodeStructValue,
		reflect.UnsafePointer: decodeUnsupportedValue,
	}
}

func getDecoder(typ reflect.Type) decoderFunc {
	kind := typ.Kind()

	if typ.Implements(customDecoderType) {
		return decodeCustomValue
	}

	// Addressable struct field value.
	if kind != reflect.Ptr && reflect.PtrTo(typ).Implements(customDecoderType) {
		return decodeCustomValuePtr
	}

	if typ.Implements(unmarshalerType) {
		return unmarshalValue
	}

	if decoder, ok := typDecMap[typ]; ok {
		return decoder
	}

	switch kind {
	case reflect.Ptr:
		return ptrDecoderFunc(typ)
	case reflect.Slice:
		elem := typ.Elem()
		switch elem.Kind() {
		case reflect.Uint8:
			return decodeBytesValue
		}
		switch elem {
		case stringType:
			return decodeStringSliceValue
		}
	case reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return decodeByteArrayValue
		}
	case reflect.Map:
		if typ.Key() == stringType {
			switch typ.Elem() {
			case stringType:
				return decodeMapStringStringValue
			case interfaceType:
				return decodeMapStringInterfaceValue
			}
		}
	}
	return valueDecoders[kind]
}

func ptrDecoderFunc(typ reflect.Type) decoderFunc {
	decoder := getDecoder(typ.Elem())
	return func(d *Decoder, v reflect.Value) error {
		if d.gotNilCode() {
			v.Set(reflect.Zero(v.Type()))
			return d.DecodeNil()
		}
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("msgpack: Decode(nonsettable %T)", v.Interface())
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		return decoder(d, v.Elem())
	}
}

func decodeCustomValuePtr(d *Decoder, v reflect.Value) error {
	if !v.CanAddr() {
		return fmt.Errorf("msgpack: Decode(nonsettable %T)", v.Interface())
	}
	if d.gotNilCode() {
		return d.DecodeNil()
	}
	decoder := v.Addr().Interface().(CustomDecoder)
	return decoder.DecodeMsgpack(d)
}

func decodeCustomValue(d *Decoder, v reflect.Value) error {
	if d.gotNilCode() {
		return d.DecodeNil()
	}
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	decoder := v.Interface().(CustomDecoder)
	return decoder.DecodeMsgpack(d)
}

func unmarshalValue(d *Decoder, v reflect.Value) error {
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	b, err := ioutil.ReadAll(d.r)
	if err != nil {
		return err
	}
	unmarshaler := v.Interface().(Unmarshaler)
	return unmarshaler.UnmarshalMsgpack(b)
}

func decodeBoolValue(d *Decoder, v reflect.Value) error {
	r, err := d.DecodeBool()
	if err != nil {
		return err
	}
	v.SetBool(r)
	return nil
}

func decodeInterfaceValue(d *Decoder, v reflect.Value) error {
	if v.IsNil() {
		return d.interfaceValue(v)
	}
	return d.DecodeValue(v.Elem())
}

func decodeUnsupportedValue(d *Decoder, v reflect.Value) error {
	return fmt.Errorf("msgpack: Decode(unsupported %s)", v.Type())
}
