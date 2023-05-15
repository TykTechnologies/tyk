package structs

import (
	"go/ast"
	"go/token"
)

// StructList is a list of information for exported struct type info,
// starting from the root struct declaration(XTykGateway).
type StructList []*StructInfo

func (x StructList) Len() int           { return len(x) }
func (x StructList) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
func (x StructList) Less(i, j int) bool { return x[i].Name < x[j].Name }

func (x *StructList) append(newInfo *StructInfo) int {
	*x = append(*x, newInfo)
	return len(*x)
}

// StructInfo holds ast field information for the docs generator.
type StructInfo struct {
	// Name is struct go name.
	Name string

	// Fields holds information of the fields, if this object is a struct.
	Fields []*FieldInfo `json:"fields,omitempty"`

	// fileSet holds a token.FileSet, used to resolve symbols to file:line
	fileSet *token.FileSet

	// structObj is the raw ast.StructType value, private.
	structObj *ast.StructType
}

// FieldInfo holds details about a field.
type FieldInfo struct {
	// Doc is field docs. comments that are not part of docs are excluded.
	Doc string `json:"doc"`

	// GoName is the name of the field in Go
	GoName string `json:"go_name"`

	// GoType is the literal type of the Go field
	GoType string `json:"go_type"`

	// GoPath is the go path of this field starting from root object
	GoPath string `json:"go_path"`

	// Tag is the go tag, unmodified
	Tag string `json:"tag"`

	// JSONName is the corresponding json name of the field.
	JSONName string `json:"json_name"`

	// MapKey is the map key type, if this field is a map
	MapKey string `json:"map_key,omitempty"`

	// IsArray reports if this field is an array.
	IsArray bool `json:"is_array"`

	// fileSet holds a token.FileSet, used to resolve symbols to file:line
	fileSet *token.FileSet
}
