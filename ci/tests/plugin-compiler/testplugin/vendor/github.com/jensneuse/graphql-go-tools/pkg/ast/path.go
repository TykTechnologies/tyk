package ast

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
)

type PathKind int

const (
	UnknownPathKind PathKind = iota
	ArrayIndex
	FieldName
)

type PathItem struct {
	Kind       PathKind
	ArrayIndex int
	FieldName  ByteSlice
}

type Path []PathItem

func (p Path) Equals(another Path) bool {
	if len(p) != len(another) {
		return false
	}
	for i := range p {
		if p[i].Kind != another[i].Kind {
			return false
		}
		if p[i].Kind == ArrayIndex && p[i].ArrayIndex != another[i].ArrayIndex {
			return false
		} else if !bytes.Equal(p[i].FieldName, another[i].FieldName) {
			return false
		}
	}
	return true
}

func (p Path) String() string {
	out := "["
	for i := range p {
		if i != 0 {
			out += ","
		}
		switch p[i].Kind {
		case ArrayIndex:
			out += strconv.Itoa(p[i].ArrayIndex)
		case FieldName:
			if len(p[i].FieldName) == 0 {
				out += "query"
			} else {
				out += unsafebytes.BytesToString(p[i].FieldName)
			}
		}
	}
	out += "]"
	return out
}

func (p Path) DotDelimitedString() string {
	out := ""
	for i := range p {
		if i != 0 {
			out += "."
		}
		switch p[i].Kind {
		case ArrayIndex:
			out += strconv.Itoa(p[i].ArrayIndex)
		case FieldName:
			if len(p[i].FieldName) == 0 {
				out += "query"
			} else {
				out += unsafebytes.BytesToString(p[i].FieldName)
			}
		}
	}
	return out
}

func (p *PathItem) UnmarshalJSON(data []byte) error {
	if data == nil {
		return fmt.Errorf("data must not be nil")
	}
	if data[0] == '"' && data[len(data)-1] == '"' {
		p.Kind = FieldName
		p.FieldName = data[1 : len(data)-1]
		return nil
	}
	out, err := strconv.ParseInt(*(*string)(unsafe.Pointer(&data)), 10, 64)
	if err != nil {
		return err
	}
	p.Kind = ArrayIndex
	p.ArrayIndex = int(out)
	return nil
}

func (p PathItem) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case ArrayIndex:
		return strconv.AppendInt(nil, int64(p.ArrayIndex), 10), nil
	case FieldName:
		return append([]byte("\""), append(p.FieldName, []byte("\"")...)...), nil
	default:
		return nil, fmt.Errorf("cannot marshal unknown PathKind")
	}
}
