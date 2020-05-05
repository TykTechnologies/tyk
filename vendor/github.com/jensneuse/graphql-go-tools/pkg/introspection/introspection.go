//go:generate go-enum -f=$GOFILE --noprefix --marshal

// Package introspection takes a GraphQL Schema and provides the introspection JSON to fulfill introspection queries.
package introspection

import (
	"bytes"
)

type Data struct {
	Schema Schema `json:"__schema"`
}

type Schema struct {
	QueryType        *TypeName   `json:"queryType"`
	MutationType     *TypeName   `json:"mutationType"`
	SubscriptionType *TypeName   `json:"subscriptionType"`
	Types            []FullType  `json:"types"`
	Directives       []Directive `json:"directives"`
}

func NewSchema() Schema {
	return Schema{
		Types:      make([]FullType, 0),
		Directives: make([]Directive, 0),
	}
}

type TypeName struct {
	Name string `json:"name"`
}

type FullType struct {
	Kind          __TypeKind   `json:"kind"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Fields        []Field      `json:"fields"`
	InputFields   []InputValue `json:"inputFields"`
	Interfaces    []TypeRef    `json:"interfaces"`
	EnumValues    []EnumValue  `json:"enumValues"`
	PossibleTypes []TypeRef    `json:"possibleTypes"`
}

func NewFullType() FullType {
	return FullType{
		Fields:        make([]Field, 0),
		InputFields:   make([]InputValue, 0),
		Interfaces:    make([]TypeRef, 0),
		EnumValues:    make([]EnumValue, 0),
		PossibleTypes: make([]TypeRef, 0),
	}
}

/*
ENUM(
SCALAR
LIST
NON_NULL
OBJECT
ENUM
INTERFACE
UNION
INPUT_OBJECT
)
*/
type __TypeKind int

func (x __TypeKind) MarshalJSON() ([]byte, error) {

	text, err := x.MarshalText()
	if err != nil {
		return nil, err
	}

	var buff bytes.Buffer
	_, err = buff.WriteRune('"')
	if err != nil {
		return nil, err
	}
	_, err = buff.Write(text)
	if err != nil {
		return nil, err
	}
	_, err = buff.WriteRune('"')

	return buff.Bytes(), err
}

type TypeRef struct {
	Kind   __TypeKind `json:"kind"`
	Name   *string    `json:"name"`
	OfType *TypeRef   `json:"ofType"`
}

type Field struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Args        []InputValue `json:"args"`
	Type        TypeRef      `json:"type"`
	//IsDeprecated      *bool        `json:"isDeprecated"`
	//DeprecationReason string       `json:"deprecationReason"`
}

func NewField() Field {
	return Field{
		Args: make([]InputValue, 0),
	}
}

type EnumValue struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	//IsDeprecated      *bool   `json:"isDeprecated"`
	//DeprecationReason *string `json:"deprecationReason"`
}

type InputValue struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Type         TypeRef `json:"type"`
	DefaultValue *string `json:"defaultValue"`
}

type Directive struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Locations   []string     `json:"locations"`
	Args        []InputValue `json:"args"`
}

func NewDirective() Directive {
	return Directive{
		Locations: make([]string, 0),
		Args:      make([]InputValue, 0),
	}
}
