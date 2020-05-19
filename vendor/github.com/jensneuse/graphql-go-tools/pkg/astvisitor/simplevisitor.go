package astvisitor

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
)

type SimpleWalker struct {
	err              error
	document         *ast.Document
	Depth            int
	Ancestors        []ast.Node
	visitor          AllNodesVisitor
	SelectionsBefore []int
	SelectionsAfter  []int
}

func NewSimpleWalker(ancestorSize int) SimpleWalker {
	return SimpleWalker{
		Ancestors: make([]ast.Node, 0, ancestorSize),
	}
}

func (w *SimpleWalker) SetVisitor(visitor AllNodesVisitor) {
	w.visitor = visitor
}

func (w *SimpleWalker) Walk(document, definition *ast.Document) error {
	return w.WalkDocument(document)
}

func (w *SimpleWalker) WalkDocument(document *ast.Document) error {

	if w.visitor == nil {
		return fmt.Errorf("visitor must not be nil, use SetVisitor()")
	}

	w.err = nil
	w.Ancestors = w.Ancestors[:0]
	w.document = document
	w.Depth = 0
	w.walk()
	return w.err
}

func (w *SimpleWalker) appendAncestor(ref int, kind ast.NodeKind) {
	w.Ancestors = append(w.Ancestors, ast.Node{
		Kind: kind,
		Ref:  ref,
	})
}

func (w *SimpleWalker) removeLastAncestor() {
	w.Ancestors = w.Ancestors[:len(w.Ancestors)-1]
}

func (w *SimpleWalker) increaseDepth() {
	w.Depth++
}

func (w *SimpleWalker) decreaseDepth() {
	w.Depth--
}

func (w *SimpleWalker) walk() {

	if w.document == nil {
		w.err = fmt.Errorf("document must not be nil")
		return
	}

	w.visitor.EnterDocument(w.document, nil)

	for i := range w.document.RootNodes {
		isLast := i == len(w.document.RootNodes)-1
		switch w.document.RootNodes[i].Kind {
		case ast.NodeKindOperationDefinition:
			w.walkOperationDefinition(w.document.RootNodes[i].Ref, isLast)
		case ast.NodeKindFragmentDefinition:
			w.walkFragmentDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindSchemaDefinition:
			w.walkSchemaDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindSchemaExtension:
			w.walkSchemaExtension(w.document.RootNodes[i].Ref)
		case ast.NodeKindDirectiveDefinition:
			w.walkDirectiveDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindObjectTypeDefinition:
			w.walkObjectTypeDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindObjectTypeExtension:
			w.walkObjectTypeExtension(w.document.RootNodes[i].Ref)
		case ast.NodeKindInterfaceTypeDefinition:
			w.walkInterfaceTypeDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindInterfaceTypeExtension:
			w.walkInterfaceTypeExtension(w.document.RootNodes[i].Ref)
		case ast.NodeKindScalarTypeDefinition:
			w.walkScalarTypeDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindScalarTypeExtension:
			w.walkScalarTypeExtension(w.document.RootNodes[i].Ref)
		case ast.NodeKindUnionTypeDefinition:
			w.walkUnionTypeDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindUnionTypeExtension:
			w.walkUnionTypeExtension(w.document.RootNodes[i].Ref)
		case ast.NodeKindEnumTypeDefinition:
			w.walkEnumTypeDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindEnumTypeExtension:
			w.walkEnumTypeExtension(w.document.RootNodes[i].Ref)
		case ast.NodeKindInputObjectTypeDefinition:
			w.walkInputObjectTypeDefinition(w.document.RootNodes[i].Ref)
		case ast.NodeKindInputObjectTypeExtension:
			w.walkInputObjectTypeExtension(w.document.RootNodes[i].Ref)
		}
	}

	w.visitor.LeaveDocument(w.document, nil)
}

func (w *SimpleWalker) walkOperationDefinition(ref int, isLastRootNode bool) {
	w.increaseDepth()

	w.visitor.EnterOperationDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindOperationDefinition)

	if w.document.OperationDefinitions[ref].HasVariableDefinitions {
		for _, i := range w.document.OperationDefinitions[ref].VariableDefinitions.Refs {
			w.walkVariableDefinition(i)
		}
	}

	if w.document.OperationDefinitions[ref].HasDirectives {
		for _, i := range w.document.OperationDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.OperationDefinitions[ref].HasSelections {
		w.walkSelectionSet(w.document.OperationDefinitions[ref].SelectionSet)
	}

	w.removeLastAncestor()

	w.visitor.LeaveOperationDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkVariableDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterVariableDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindVariableDefinition)

	if w.document.VariableDefinitions[ref].HasDirectives {
		for _, i := range w.document.VariableDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveVariableDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkSelectionSet(ref int) {
	w.increaseDepth()

	w.visitor.EnterSelectionSet(ref)

	w.appendAncestor(ref, ast.NodeKindSelectionSet)

	for i, j := range w.document.SelectionSets[ref].SelectionRefs {

		w.SelectionsBefore = w.document.SelectionSets[ref].SelectionRefs[:i]
		w.SelectionsAfter = w.document.SelectionSets[ref].SelectionRefs[i+1:]

		switch w.document.Selections[j].Kind {
		case ast.SelectionKindField:
			w.walkField(w.document.Selections[j].Ref)
		case ast.SelectionKindFragmentSpread:
			w.walkFragmentSpread(w.document.Selections[j].Ref)
		case ast.SelectionKindInlineFragment:
			w.walkInlineFragment(w.document.Selections[j].Ref)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveSelectionSet(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkField(ref int) {
	w.increaseDepth()

	selectionsBefore := w.SelectionsBefore
	selectionsAfter := w.SelectionsAfter
	w.visitor.EnterField(ref)

	w.appendAncestor(ref, ast.NodeKindField)

	if len(w.document.Fields[ref].Arguments.Refs) != 0 {
		for _, i := range w.document.Fields[ref].Arguments.Refs {
			w.walkArgument(i)
		}
	}

	if w.document.Fields[ref].HasDirectives {
		for _, i := range w.document.Fields[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.Fields[ref].HasSelections {
		w.walkSelectionSet(w.document.Fields[ref].SelectionSet)
	}

	w.removeLastAncestor()

	w.SelectionsBefore = selectionsBefore
	w.SelectionsAfter = selectionsAfter
	w.visitor.LeaveField(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkDirective(ref int) {
	w.increaseDepth()

	w.visitor.EnterDirective(ref)

	w.appendAncestor(ref, ast.NodeKindDirective)

	if w.document.Directives[ref].HasArguments {
		for _, i := range w.document.Directives[ref].Arguments.Refs {
			w.walkArgument(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveDirective(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkArgument(ref int) {
	w.increaseDepth()

	w.visitor.EnterArgument(ref)
	w.visitor.LeaveArgument(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkFragmentSpread(ref int) {
	w.increaseDepth()

	w.visitor.EnterFragmentSpread(ref)
	w.visitor.LeaveFragmentSpread(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkInlineFragment(ref int) {
	w.increaseDepth()

	selectionsBefore := w.SelectionsBefore
	selectionsAfter := w.SelectionsAfter
	w.visitor.EnterInlineFragment(ref)

	w.appendAncestor(ref, ast.NodeKindInlineFragment)

	if w.document.InlineFragments[ref].HasDirectives {
		for _, i := range w.document.InlineFragments[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.InlineFragments[ref].HasSelections {
		w.walkSelectionSet(w.document.InlineFragments[ref].SelectionSet)
	}

	w.removeLastAncestor()

	w.SelectionsBefore = selectionsBefore
	w.SelectionsAfter = selectionsAfter
	w.visitor.LeaveInlineFragment(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkFragmentDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterFragmentDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindFragmentDefinition)

	if w.document.FragmentDefinitions[ref].HasSelections {
		w.walkSelectionSet(w.document.FragmentDefinitions[ref].SelectionSet)
	}

	w.removeLastAncestor()

	w.visitor.LeaveFragmentDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkObjectTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterObjectTypeDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindObjectTypeDefinition)

	if w.document.ObjectTypeDefinitions[ref].HasDirectives {
		for _, i := range w.document.ObjectTypeDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.ObjectTypeDefinitions[ref].HasFieldDefinitions {
		for _, i := range w.document.ObjectTypeDefinitions[ref].FieldsDefinition.Refs {
			w.walkFieldDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveObjectTypeDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkObjectTypeExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterObjectTypeExtension(ref)
	w.appendAncestor(ref, ast.NodeKindObjectTypeExtension)

	if w.document.ObjectTypeExtensions[ref].HasDirectives {
		for _, i := range w.document.ObjectTypeExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.ObjectTypeExtensions[ref].HasFieldDefinitions {
		for _, i := range w.document.ObjectTypeExtensions[ref].FieldsDefinition.Refs {
			w.walkFieldDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveObjectTypeExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkFieldDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterFieldDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindFieldDefinition)

	if w.document.FieldDefinitions[ref].HasArgumentsDefinitions {
		for _, i := range w.document.FieldDefinitions[ref].ArgumentsDefinition.Refs {
			w.walkInputValueDefinition(i)
		}
	}

	if w.document.FieldDefinitions[ref].HasDirectives {
		for _, i := range w.document.FieldDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveFieldDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkInputValueDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterInputValueDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindInputValueDefinition)

	if w.document.InputValueDefinitions[ref].HasDirectives {
		for _, i := range w.document.InputValueDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveInputValueDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkInterfaceTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterInterfaceTypeDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindInterfaceTypeDefinition)

	if w.document.InterfaceTypeDefinitions[ref].HasDirectives {
		for _, i := range w.document.InterfaceTypeDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.InterfaceTypeDefinitions[ref].HasFieldDefinitions {
		for _, i := range w.document.InterfaceTypeDefinitions[ref].FieldsDefinition.Refs {
			w.walkFieldDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveInterfaceTypeDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkInterfaceTypeExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterInterfaceTypeExtension(ref)

	w.appendAncestor(ref, ast.NodeKindInterfaceTypeExtension)

	if w.document.InterfaceTypeExtensions[ref].HasDirectives {
		for _, i := range w.document.InterfaceTypeExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.InterfaceTypeExtensions[ref].HasFieldDefinitions {
		for _, i := range w.document.InterfaceTypeExtensions[ref].FieldsDefinition.Refs {
			w.walkFieldDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveInterfaceTypeExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkScalarTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterScalarTypeDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindScalarTypeDefinition)

	if w.document.ScalarTypeDefinitions[ref].HasDirectives {
		for _, i := range w.document.ScalarTypeDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveScalarTypeDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkScalarTypeExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterScalarTypeExtension(ref)

	w.appendAncestor(ref, ast.NodeKindScalarTypeExtension)

	if w.document.ScalarTypeExtensions[ref].HasDirectives {
		for _, i := range w.document.ScalarTypeExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveScalarTypeExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkUnionTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterUnionTypeDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindUnionTypeDefinition)

	if w.document.UnionTypeDefinitions[ref].HasDirectives {
		for _, i := range w.document.UnionTypeDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.UnionTypeDefinitions[ref].HasUnionMemberTypes {
		for _, i := range w.document.UnionTypeDefinitions[ref].UnionMemberTypes.Refs {
			w.walkUnionMemberType(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveUnionTypeDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkUnionTypeExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterUnionTypeExtension(ref)

	w.appendAncestor(ref, ast.NodeKindUnionTypeExtension)

	if w.document.UnionTypeExtensions[ref].HasDirectives {
		for _, i := range w.document.UnionTypeExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.UnionTypeExtensions[ref].HasUnionMemberTypes {
		for _, i := range w.document.UnionTypeExtensions[ref].UnionMemberTypes.Refs {
			w.walkUnionMemberType(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveUnionTypeExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkUnionMemberType(ref int) {
	w.increaseDepth()

	w.visitor.EnterUnionMemberType(ref)

	w.visitor.LeaveUnionMemberType(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkEnumTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterEnumTypeDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindEnumTypeDefinition)

	if w.document.EnumTypeDefinitions[ref].HasDirectives {
		for _, i := range w.document.EnumTypeDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.EnumTypeDefinitions[ref].HasEnumValuesDefinition {
		for _, i := range w.document.EnumTypeDefinitions[ref].EnumValuesDefinition.Refs {
			w.walkEnumValueDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveEnumTypeDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkEnumTypeExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterEnumTypeExtension(ref)

	w.appendAncestor(ref, ast.NodeKindEnumTypeExtension)

	if w.document.EnumTypeExtensions[ref].HasDirectives {
		for _, i := range w.document.EnumTypeExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.EnumTypeExtensions[ref].HasEnumValuesDefinition {
		for _, i := range w.document.EnumTypeExtensions[ref].EnumValuesDefinition.Refs {
			w.walkEnumValueDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveEnumTypeExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkEnumValueDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterEnumValueDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindEnumValueDefinition)

	if w.document.EnumValueDefinitions[ref].HasDirectives {
		for _, i := range w.document.EnumValueDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveEnumValueDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkInputObjectTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterInputObjectTypeDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindInputObjectTypeDefinition)

	if w.document.InputObjectTypeDefinitions[ref].HasDirectives {
		for _, i := range w.document.InputObjectTypeDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.InputObjectTypeDefinitions[ref].HasInputFieldsDefinition {
		for _, i := range w.document.InputObjectTypeDefinitions[ref].InputFieldsDefinition.Refs {
			w.walkInputValueDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveInputObjectTypeDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkInputObjectTypeExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterInputObjectTypeExtension(ref)

	w.appendAncestor(ref, ast.NodeKindInputObjectTypeExtension)

	if w.document.InputObjectTypeExtensions[ref].HasDirectives {
		for _, i := range w.document.InputObjectTypeExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	if w.document.InputObjectTypeExtensions[ref].HasInputFieldsDefinition {
		for _, i := range w.document.InputObjectTypeExtensions[ref].InputFieldsDefinition.Refs {
			w.walkInputValueDefinition(i)
		}
	}

	w.removeLastAncestor()

	w.visitor.LeaveInputObjectTypeExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkDirectiveDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterDirectiveDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindDirectiveDefinition)

	if w.document.DirectiveDefinitions[ref].HasArgumentsDefinitions {
		for _, i := range w.document.DirectiveDefinitions[ref].ArgumentsDefinition.Refs {
			w.walkInputValueDefinition(i)
		}
	}

	iter := w.document.DirectiveDefinitions[ref].DirectiveLocations.Iterable()
	for iter.Next() {
		w.walkDirectiveLocation(iter.Value())
	}

	w.removeLastAncestor()

	w.visitor.LeaveDirectiveDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkDirectiveLocation(location ast.DirectiveLocation) {
	w.increaseDepth()

	w.visitor.EnterDirectiveLocation(location)

	w.visitor.LeaveDirectiveLocation(location)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkSchemaDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterSchemaDefinition(ref)

	w.appendAncestor(ref, ast.NodeKindSchemaDefinition)

	if w.document.SchemaDefinitions[ref].HasDirectives {
		for _, i := range w.document.SchemaDefinitions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	for _, i := range w.document.SchemaDefinitions[ref].RootOperationTypeDefinitions.Refs {
		w.walkRootOperationTypeDefinition(i)
	}

	w.removeLastAncestor()

	w.visitor.LeaveSchemaDefinition(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkSchemaExtension(ref int) {
	w.increaseDepth()

	w.visitor.EnterSchemaExtension(ref)

	w.appendAncestor(ref, ast.NodeKindSchemaExtension)

	if w.document.SchemaExtensions[ref].HasDirectives {
		for _, i := range w.document.SchemaExtensions[ref].Directives.Refs {
			w.walkDirective(i)
		}
	}

	for _, i := range w.document.SchemaExtensions[ref].RootOperationTypeDefinitions.Refs {
		w.walkRootOperationTypeDefinition(i)
	}

	w.removeLastAncestor()

	w.visitor.LeaveSchemaExtension(ref)

	w.decreaseDepth()
}

func (w *SimpleWalker) walkRootOperationTypeDefinition(ref int) {
	w.increaseDepth()

	w.visitor.EnterRootOperationTypeDefinition(ref)

	w.visitor.LeaveRootOperationTypeDefinition(ref)

	w.decreaseDepth()
}
