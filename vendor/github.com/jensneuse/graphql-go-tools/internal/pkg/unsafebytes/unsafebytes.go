package unsafebytes

import (
	"reflect"
	"strconv"
	"unsafe"
)

func BytesToInt64(byteSlice []byte) int64 {
	out, _ := strconv.ParseInt(*(*string)(unsafe.Pointer(&byteSlice)), 10, 64)
	return out
}

func BytesToFloat32(byteSlice []byte) float32 {
	out, _ := strconv.ParseFloat(*(*string)(unsafe.Pointer(&byteSlice)), 64)
	return float32(out)
}

func BytesToString(bytes []byte) string {
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	stringHeader := reflect.StringHeader{Data: sliceHeader.Data, Len: sliceHeader.Len}
	return *(*string)(unsafe.Pointer(&stringHeader))
}

func BytesToBool(byteSlice []byte) bool {
	out, _ := strconv.ParseBool(*(*string)(unsafe.Pointer(&byteSlice)))
	return out
}

func StringToBytes(str string) []byte {
	hdr := *(*reflect.StringHeader)(unsafe.Pointer(&str))
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: hdr.Data,
		Len:  hdr.Len,
		Cap:  hdr.Len,
	}))
}

func BytesIsValidFloat32(byteSlice []byte) bool {
	_, err := strconv.ParseFloat(*(*string)(unsafe.Pointer(&byteSlice)), 64)
	return err == nil
}

func BytesIsValidInt64(byteSlice []byte) bool {
	_, err := strconv.ParseInt(*(*string)(unsafe.Pointer(&byteSlice)), 10, 64)
	return err == nil
}

func BytesIsValidBool(byteSlice []byte) bool {
	_, err := strconv.ParseBool(*(*string)(unsafe.Pointer(&byteSlice)))
	return err == nil
}
