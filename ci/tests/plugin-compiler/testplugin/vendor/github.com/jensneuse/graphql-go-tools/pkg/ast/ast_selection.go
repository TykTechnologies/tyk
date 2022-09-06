package ast

import (
	"bytes"
	"fmt"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type SelectionKind int

const (
	SelectionKindUnknown SelectionKind = 18 + iota
	SelectionKindField
	SelectionKindFragmentSpread
	SelectionKindInlineFragment
)

type SelectionSet struct {
	LBrace        position.Position
	RBrace        position.Position
	SelectionRefs []int
}

type Selection struct {
	Kind SelectionKind // one of Field, FragmentSpread, InlineFragment
	Ref  int           // reference to the actual selection
}

func (d *Document) PrintSelections(selections []int) (out string) {
	out += "["
	for i, ref := range selections {
		out += fmt.Sprintf("%+v", d.Selections[ref])
		if i != len(selections)-1 {
			out += ","
		}
	}
	out += "]"
	return
}

func (d *Document) SelectionsBeforeField(field int, selectionSet Node) bool {
	if selectionSet.Kind != NodeKindSelectionSet {
		return false
	}

	if len(d.SelectionSets[selectionSet.Ref].SelectionRefs) == 1 {
		return false
	}

	for i, j := range d.SelectionSets[selectionSet.Ref].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindField && d.Selections[j].Ref == field {
			return i != 0
		}
	}

	return false
}

func (d *Document) SelectionsAfterField(field int, selectionSet Node) bool {
	if selectionSet.Kind != NodeKindSelectionSet {
		return false
	}

	if len(d.SelectionSets[selectionSet.Ref].SelectionRefs) == 1 {
		return false
	}

	for i, j := range d.SelectionSets[selectionSet.Ref].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindField && d.Selections[j].Ref == field {
			return i != len(d.SelectionSets[selectionSet.Ref].SelectionRefs)-1
		}
	}

	return false
}

func (d *Document) SelectionsAfterInlineFragment(inlineFragment int, selectionSet Node) bool {
	if selectionSet.Kind != NodeKindSelectionSet {
		return false
	}

	if len(d.SelectionSets[selectionSet.Ref].SelectionRefs) == 1 {
		return false
	}

	for i, j := range d.SelectionSets[selectionSet.Ref].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindInlineFragment && d.Selections[j].Ref == inlineFragment {
			return i != len(d.SelectionSets[selectionSet.Ref].SelectionRefs)-1
		}
	}

	return false
}

func (d *Document) AddSelectionSet() Node {
	d.SelectionSets = append(d.SelectionSets, SelectionSet{SelectionRefs: d.Refs[d.NextRefIndex()][:0]})
	return Node{
		Kind: NodeKindSelectionSet,
		Ref:  len(d.SelectionSets) - 1,
	}
}

func (d *Document) AddSelection(set int, selection Selection) {
	d.Selections = append(d.Selections, selection)
	d.SelectionSets[set].SelectionRefs = append(d.SelectionSets[set].SelectionRefs, len(d.Selections)-1)
}

func (d *Document) EmptySelectionSet(ref int) {
	d.SelectionSets[ref].SelectionRefs = d.SelectionSets[ref].SelectionRefs[:0]
}

func (d *Document) AppendSelectionSet(ref int, appendRef int) {
	d.SelectionSets[ref].SelectionRefs = append(d.SelectionSets[ref].SelectionRefs, d.SelectionSets[appendRef].SelectionRefs...)
}

func (d *Document) ReplaceSelectionOnSelectionSet(ref, replace, with int) {
	d.SelectionSets[ref].SelectionRefs = append(d.SelectionSets[ref].SelectionRefs[:replace], append(d.SelectionSets[with].SelectionRefs, d.SelectionSets[ref].SelectionRefs[replace+1:]...)...)
}

func (d *Document) RemoveFromSelectionSet(ref int, index int) {
	d.SelectionSets[ref].SelectionRefs = append(d.SelectionSets[ref].SelectionRefs[:index], d.SelectionSets[ref].SelectionRefs[index+1:]...)
}

func (d *Document) SelectionSetHasFieldSelectionWithNameOrAliasBytes(set int, nameOrAlias []byte) bool {
	for _, i := range d.SelectionSets[set].SelectionRefs {
		if d.Selections[i].Kind != SelectionKindField {
			continue
		}
		field := d.Selections[i].Ref
		fieldName := d.FieldNameBytes(field)
		if bytes.Equal(fieldName, nameOrAlias) {
			return true
		}
		if !d.FieldAliasIsDefined(field) {
			continue
		}
		fieldAlias := d.FieldAliasBytes(field)
		if bytes.Equal(fieldAlias, nameOrAlias) {
			return true
		}
	}
	return false
}

func (d *Document) SelectionSetHasFieldSelectionWithNameOrAliasString(set int, nameOrAlias string) bool {
	return d.SelectionSetHasFieldSelectionWithNameOrAliasBytes(set, unsafebytes.StringToBytes(nameOrAlias))
}
