package abstractlogger

type Field struct {
	kind           FieldKind
	key            string
	stringValue    string
	stringsValue   []string
	intValue       int64
	byteValue      []byte
	interfaceValue interface{}
	errorValue     error
}

type FieldKind int

const (
	StringField FieldKind = iota + 1
	StringsField
	IntField
	BoolField
	ByteStringField
	InterfaceField
	ErrorField
	NamedErrorField
)

func Any(key string, value interface{}) Field {
	return Field{
		kind:           InterfaceField,
		key:            key,
		interfaceValue: value,
	}
}

func Error(err error) Field {
	return Field{
		kind:       ErrorField,
		key:        "error",
		errorValue: err,
	}
}

func NamedError(key string, err error) Field {
	return Field{
		kind:       NamedErrorField,
		key:        key,
		errorValue: err,
	}
}

func String(key, value string) Field {
	return Field{
		kind:        StringField,
		key:         key,
		stringValue: value,
	}
}

func Strings(key string, value []string) Field {
	return Field{
		key:          key,
		kind:         StringsField,
		stringsValue: value,
	}
}

func Int(key string, value int) Field {
	return Field{
		kind:     IntField,
		key:      key,
		intValue: int64(value),
	}
}

func Bool(key string, value bool) Field {
	var integer int64
	if value {
		integer = 1
	}
	return Field{
		kind:     BoolField,
		key:      key,
		intValue: integer,
	}
}

func ByteString(key string, value []byte) Field {
	return Field{
		kind:      ByteStringField,
		key:       key,
		byteValue: value,
	}
}
