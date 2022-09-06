package ast

import (
	"bytes"
	"io"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type TypeKind int

const (
	TypeKindUnknown TypeKind = 14 + iota
	TypeKindNamed
	TypeKindList
	TypeKindNonNull
)

type Type struct {
	TypeKind TypeKind           // one of Named,List,NonNull
	Name     ByteSliceReference // e.g. String (only on NamedType)
	Open     position.Position  // [ (only on ListType)
	Close    position.Position  // ] (only on ListType)
	Bang     position.Position  // ! (only on NonNullType)
	OfType   int
}

func (d *Document) TypeNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Types[ref].Name)
}

func (d *Document) TypeNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.Types[ref].Name))
}

func (d *Document) PrintType(ref int, w io.Writer) error {
	switch d.Types[ref].TypeKind {
	case TypeKindNonNull:
		err := d.PrintType(d.Types[ref].OfType, w)
		if err != nil {
			return err
		}
		_, err = w.Write(literal.BANG)
		return err
	case TypeKindNamed:
		_, err := w.Write(d.Input.ByteSlice(d.Types[ref].Name))
		return err
	case TypeKindList:
		_, err := w.Write(literal.LBRACK)
		if err != nil {
			return err
		}
		err = d.PrintType(d.Types[ref].OfType, w)
		if err != nil {
			return err
		}
		_, err = w.Write(literal.RBRACK)
		return err
	}
	return nil
}

func (d *Document) PrintTypeBytes(ref int, buf []byte) ([]byte, error) {
	if buf == nil {
		buf = make([]byte, 0, 24)
	}
	b := bytes.NewBuffer(buf)
	err := d.PrintType(ref, b)
	return b.Bytes(), err
}

func (d *Document) AddType(t Type) (ref int) {
	d.Types = append(d.Types, t)
	return len(d.Types) - 1
}

func (d *Document) AddNamedType(name []byte) (ref int) {
	nameRef := d.Input.AppendInputBytes(name)
	d.Types = append(d.Types, Type{
		TypeKind: TypeKindNamed,
		Name:     nameRef,
	})
	return len(d.Types) - 1
}

func (d *Document) AddNonNullNamedType(name []byte) (ref int) {
	namedRef := d.AddNamedType(name)
	d.Types = append(d.Types, Type{
		TypeKind: TypeKindNonNull,
		OfType:   namedRef,
	})
	return len(d.Types) - 1
}

func (d *Document) TypesAreEqualDeep(left int, right int) bool {
	for {
		if left == -1 || right == -1 {
			return false
		}
		if d.Types[left].TypeKind != d.Types[right].TypeKind {
			return false
		}
		if d.Types[left].TypeKind == TypeKindNamed {
			leftName := d.TypeNameBytes(left)
			rightName := d.TypeNameBytes(right)
			return bytes.Equal(leftName, rightName)
		}
		left = d.Types[left].OfType
		right = d.Types[right].OfType
	}
}

func (d *Document) TypeIsScalar(ref int, definition *Document) bool {
	switch d.Types[ref].TypeKind {
	case TypeKindNamed:
		typeName := d.TypeNameBytes(ref)
		node, _ := definition.Index.FirstNodeByNameBytes(typeName)
		return node.Kind == NodeKindScalarTypeDefinition
	case TypeKindNonNull:
		return d.TypeIsScalar(d.Types[ref].OfType, definition)
	}
	return false
}

func (d *Document) TypeIsNonNull(ref int) bool {
	return d.Types[ref].TypeKind == TypeKindNonNull
}

func (d *Document) TypeIsList(ref int) bool {
	switch d.Types[ref].TypeKind {
	case TypeKindList:
		return true
	case TypeKindNonNull:
		return d.TypeIsList(d.Types[ref].OfType)
	default:
		return false
	}
}

func (d *Document) TypesAreCompatibleDeep(left int, right int) bool {
	for {
		if left == -1 || right == -1 {
			return false
		}
		if d.Types[left].TypeKind != d.Types[right].TypeKind {
			return false
		}
		if d.Types[left].TypeKind == TypeKindNamed {
			leftName := d.TypeNameBytes(left)
			rightName := d.TypeNameBytes(right)
			if bytes.Equal(leftName, rightName) {
				return true
			}
			leftNode, _ := d.Index.FirstNodeByNameBytes(leftName)
			rightNode, _ := d.Index.FirstNodeByNameBytes(rightName)
			if leftNode.Kind == rightNode.Kind {
				return false
			}
			if leftNode.Kind == NodeKindInterfaceTypeDefinition && rightNode.Kind == NodeKindObjectTypeDefinition {
				return d.NodeImplementsInterface(rightNode, leftNode)
			}
			if leftNode.Kind == NodeKindObjectTypeDefinition && rightNode.Kind == NodeKindInterfaceTypeDefinition {
				return d.NodeImplementsInterface(leftNode, rightNode)
			}
			if leftNode.Kind == NodeKindUnionTypeDefinition && rightNode.Kind == NodeKindObjectTypeDefinition {
				return d.NodeIsUnionMember(rightNode, leftNode)
			}
			if leftNode.Kind == NodeKindObjectTypeDefinition && rightNode.Kind == NodeKindUnionTypeDefinition {
				return d.NodeIsUnionMember(leftNode, rightNode)
			}
			return false
		}
		left = d.Types[left].OfType
		right = d.Types[right].OfType
	}
}

func (d *Document) ResolveTypeNameBytes(ref int) ByteSlice {
	graphqlType := d.Types[ref]
	for graphqlType.TypeKind != TypeKindNamed {
		graphqlType = d.Types[graphqlType.OfType]
	}
	return d.Input.ByteSlice(graphqlType.Name)
}

func (d *Document) ResolveTypeNameString(ref int) string {
	return unsafebytes.BytesToString(d.ResolveTypeNameBytes(ref))
}

func (d *Document) TypeValueNeedsQuotes(ref int, definition *Document) bool {
	graphqlType := d.Types[ref]
	switch graphqlType.TypeKind {
	case TypeKindNonNull:
		return d.TypeValueNeedsQuotes(graphqlType.OfType, definition)
	case TypeKindList:
		return false
	case TypeKindNamed:
		typeName := d.Input.ByteSliceString(graphqlType.Name)
		switch typeName {
		case "String", "Date", "ID":
			return true
		default:
			node, _ := definition.Index.FirstNodeByNameStr(typeName)
			return node.Kind == NodeKindEnumTypeDefinition
		}
	default:
		return false
	}
}
