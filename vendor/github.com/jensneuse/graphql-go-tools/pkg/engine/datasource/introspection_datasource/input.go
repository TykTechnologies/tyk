package introspection_datasource

import (
	"bytes"
	"strconv"
)

type requestType int

const (
	SchemaRequestType requestType = iota + 1
	TypeRequestType
	TypeFieldsRequestType
	TypeEnumValuesRequestType
)

const (
	schemaFieldName     = "__schema"
	typeFieldName       = "__type"
	fieldsFieldName     = "fields"
	enumValuesFieldName = "enumValues"
)

type introspectionInput struct {
	RequestType       requestType `json:"request_type"`
	OnTypeName        *string     `json:"on_type_name"`
	TypeName          *string     `json:"type_name"`
	IncludeDeprecated bool        `json:"include_deprecated"`
}

var (
	lBrace                 = []byte("{")
	rBrace                 = []byte("}")
	comma                  = []byte(",")
	requestTypeField       = []byte(`"request_type":`)
	onTypeField            = []byte(`"on_type_name":{{ .object.name }}`)
	typeNameField          = []byte(`"type_name":"{{ .arguments.name }}"`)
	includeDeprecatedField = []byte(`"include_deprecated":{{ .arguments.includeDeprecated }}`)
)

func buildInput(fieldName string) string {
	buf := &bytes.Buffer{}
	buf.Write(lBrace)

	switch fieldName {
	case typeFieldName:
		writeRequestTypeField(buf, TypeRequestType)
		buf.Write(comma)
		buf.Write(typeNameField)
	case fieldsFieldName:
		writeRequestTypeField(buf, TypeFieldsRequestType)
		writeOnTypeFields(buf)
	case enumValuesFieldName:
		writeRequestTypeField(buf, TypeEnumValuesRequestType)
		writeOnTypeFields(buf)
	default:
		writeRequestTypeField(buf, SchemaRequestType)
	}

	buf.Write(rBrace)

	return buf.String()
}

func writeRequestTypeField(buf *bytes.Buffer, inputType requestType) {
	buf.Write(requestTypeField)
	buf.Write([]byte(strconv.Itoa(int(inputType))))
}

func writeOnTypeFields(buf *bytes.Buffer) {
	buf.Write(comma)
	buf.Write(onTypeField)
	buf.Write(comma)
	buf.Write(includeDeprecatedField)
}
