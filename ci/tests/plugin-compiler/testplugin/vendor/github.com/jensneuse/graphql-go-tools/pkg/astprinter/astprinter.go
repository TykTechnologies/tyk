// Package astprinter takes a GraphQL document and prints it as a String with optional indentation.
package astprinter

import (
	"bytes"
	"io"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

// Print takes a document as well as a definition (optional) and prints it to the io.Writer.
// The definition is only necessary in case a GraphQL Operation should be printed.
func Print(document, definition *ast.Document, out io.Writer) error {
	printer := Printer{}
	return printer.Print(document, definition, out)
}

// PrintIndent is the same as Print but accepts an additional indent parameter to set indentation.
func PrintIndent(document, definition *ast.Document, indent []byte, out io.Writer) error {
	printer := Printer{
		indent: indent,
	}
	return printer.Print(document, definition, out)
}

// PrintString is the same as Print but returns a string instead of writing to an io.Writer
func PrintString(document, definition *ast.Document) (string, error) {
	buff := &bytes.Buffer{}
	err := Print(document, definition, buff)
	out := buff.String()
	return out, err
}

// PrintStringIndent is the same as PrintIndent but returns a string instead of writing to an io.Writer
func PrintStringIndent(document, definition *ast.Document, indent string) (string, error) {
	buff := &bytes.Buffer{}
	err := PrintIndent(document, definition, []byte(indent), buff)
	out := buff.String()
	return out, err
}

// Printer walks a GraphQL document and prints it as a string
type Printer struct {
	indent     []byte
	visitor    printVisitor
	walker     astvisitor.SimpleWalker
	registered bool
}

// Print starts the actual AST printing
// Keep a printer and re-use it in case you'd like to print ASTs in the hot path.
func (p *Printer) Print(document, definition *ast.Document, out io.Writer) error {
	p.visitor.indent = p.indent
	p.visitor.err = nil
	p.visitor.document = document
	p.visitor.out = out
	p.visitor.SimpleWalker = &p.walker
	if !p.registered {
		p.walker.SetVisitor(&p.visitor)
	}
	return p.walker.Walk(p.visitor.document, definition)
}

type printVisitor struct {
	*astvisitor.SimpleWalker
	document *ast.Document
	out      io.Writer
	err      error

	indent                     []byte
	inputValueDefinitionOpener []byte
	inputValueDefinitionCloser []byte
	isFirstDirectiveLocation   bool
}

func (p *printVisitor) write(data []byte) {
	if p.err != nil {
		return
	}
	_, p.err = p.out.Write(data)
}

func (p *printVisitor) indentationDepth() (depth int) {

	if len(p.Ancestors) == 0 {
		return 0
	}

	switch p.Ancestors[0].Kind {
	case ast.NodeKindOperationDefinition,
		ast.NodeKindFragmentDefinition:
	default:
		return 2
	}

	for i := range p.Ancestors {
		if p.Ancestors[i].Kind == ast.NodeKindSelectionSet {
			depth += 2
		}
	}

	return depth
}

func (p *printVisitor) writeIndented(data []byte) {
	if p.err != nil {
		return
	}
	depth := p.indentationDepth()
	for i := 0; i < depth; i++ {
		_, p.err = p.out.Write(p.indent)
	}
	_, p.err = p.out.Write(data)
}

func (p *printVisitor) must(err error) {
	if p.err != nil {
		return
	}
	p.err = err
}

func (p *printVisitor) EnterDirective(ref int) {
	if p.document.DirectiveIsFirst(ref, p.Ancestors[len(p.Ancestors)-1]) {
		switch p.Ancestors[len(p.Ancestors)-1].Kind {
		case ast.NodeKindFieldDefinition:
			p.writeFieldType(p.Ancestors[len(p.Ancestors)-1].Ref)
			p.write(literal.SPACE)
		case ast.NodeKindEnumValueDefinition,
			ast.NodeKindInputValueDefinition:
			p.write(literal.SPACE)
		}
	}

	p.write(literal.AT)
	p.write(p.document.DirectiveNameBytes(ref))
}

func (p *printVisitor) LeaveDirective(ref int) {
	if !p.document.DirectiveIsLast(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(literal.SPACE)
		return
	}

	ancestor := p.Ancestors[len(p.Ancestors)-1]
	switch ancestor.Kind {
	case ast.NodeKindField:
		if p.document.FieldHasSelections(ancestor.Ref) {
			p.write(literal.SPACE)
		} else if len(p.SelectionsAfter) > 0 {
			if p.indent != nil {
				p.write(literal.LINETERMINATOR)
			} else {
				p.write(literal.SPACE)
			}
		}
	case ast.NodeKindVariableDefinition:
		if !p.document.VariableDefinitionsAfter(ancestor.Ref) {
			p.write(literal.SPACE)
		}
	case ast.NodeKindInlineFragment:
		if len(p.SelectionsAfter) > 0 {
			p.write(literal.SPACE)
		}
	case ast.NodeKindScalarTypeDefinition,
		ast.NodeKindScalarTypeExtension,
		ast.NodeKindUnionTypeDefinition,
		ast.NodeKindUnionTypeExtension,
		ast.NodeKindEnumTypeDefinition,
		ast.NodeKindEnumTypeExtension,
		ast.NodeKindEnumValueDefinition,
		ast.NodeKindFieldDefinition,
		ast.NodeKindInputValueDefinition:
		return
	default:
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) EnterVariableDefinition(ref int) {
	if !p.document.VariableDefinitionsBefore(ref) {
		p.write(literal.LPAREN)
	}

	p.must(p.document.PrintValue(p.document.VariableDefinitions[ref].VariableValue, p.out))
	p.write(literal.COLON)
	p.write(literal.SPACE)

	p.must(p.document.PrintType(p.document.VariableDefinitions[ref].Type, p.out))

	if p.document.VariableDefinitions[ref].DefaultValue.IsDefined {
		p.write(literal.SPACE)
		p.write(literal.EQUALS)
		p.write(literal.SPACE)
		p.must(p.document.PrintValue(p.document.VariableDefinitions[ref].DefaultValue.Value, p.out))
	}

	if p.document.VariableDefinitions[ref].HasDirectives {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveVariableDefinition(ref int) {
	if !p.document.VariableDefinitionsAfter(ref) {
		p.write(literal.RPAREN)
	} else {
		p.write(literal.COMMA)
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) EnterArgument(ref int) {
	if len(p.document.ArgumentsBefore(p.Ancestors[len(p.Ancestors)-1], ref)) == 0 {
		p.write(literal.LPAREN)
	} else {
		p.write(literal.COMMA)
		p.write(literal.SPACE)
	}
	p.must(p.document.PrintArgument(ref, p.out))
}

func (p *printVisitor) LeaveArgument(ref int) {
	if len(p.document.ArgumentsAfter(p.Ancestors[len(p.Ancestors)-1], ref)) == 0 {
		p.write(literal.RPAREN)
	}
}

func (p *printVisitor) EnterOperationDefinition(ref int) {

	hasName := p.document.OperationDefinitions[ref].Name.Length() > 0
	hasVariables := p.document.OperationDefinitions[ref].HasVariableDefinitions

	switch p.document.OperationDefinitions[ref].OperationType {
	case ast.OperationTypeQuery:
		if hasName || hasVariables {
			p.write(literal.QUERY)
		}
	case ast.OperationTypeMutation:
		p.write(literal.MUTATION)
	case ast.OperationTypeSubscription:
		p.write(literal.SUBSCRIPTION)
	}

	if hasName {
		p.write(literal.SPACE)
	}

	if hasName {
		p.write(p.document.Input.ByteSlice(p.document.OperationDefinitions[ref].Name))
		if !p.document.OperationDefinitions[ref].HasVariableDefinitions {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) LeaveOperationDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindOperationDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterSelectionSet(ref int) {
	p.write(literal.LBRACE)
	if p.indent != nil {
		p.write(literal.LINETERMINATOR)
	}
}

func (p *printVisitor) LeaveSelectionSet(ref int) {
	if p.indent != nil {
		p.write(literal.LINETERMINATOR)
	}
	p.writeIndented(literal.RBRACE)
}

func (p *printVisitor) EnterField(ref int) {
	if p.document.Fields[ref].Alias.IsDefined {
		p.writeIndented(p.document.Input.ByteSlice(p.document.Fields[ref].Alias.Name))
		p.write(literal.COLON)
		p.write(literal.SPACE)
		p.write(p.document.Input.ByteSlice(p.document.Fields[ref].Name))
	} else {
		p.writeIndented(p.document.Input.ByteSlice(p.document.Fields[ref].Name))
	}
	if !p.document.FieldHasArguments(ref) && (p.document.FieldHasSelections(ref) || p.document.FieldHasDirectives(ref)) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveField(ref int) {
	if !p.document.FieldHasDirectives(ref) && len(p.SelectionsAfter) != 0 {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterFragmentSpread(ref int) {
	p.writeIndented(literal.SPREAD)
	p.write(p.document.Input.ByteSlice(p.document.FragmentSpreads[ref].FragmentName))
}

func (p *printVisitor) LeaveFragmentSpread(ref int) {

}

func (p *printVisitor) EnterInlineFragment(ref int) {
	p.writeIndented(literal.SPREAD)
	if p.document.InlineFragments[ref].TypeCondition.Type != -1 {
		p.write(literal.SPACE)
		p.write(literal.ON)
		p.write(literal.SPACE)
		p.write(p.document.Input.ByteSlice(p.document.Types[p.document.InlineFragments[ref].TypeCondition.Type].Name))
		p.write(literal.SPACE)
	} else if p.document.InlineFragments[ref].HasDirectives {
		p.write(literal.SPACE)
	}

}

func (p *printVisitor) LeaveInlineFragment(ref int) {
	ancestor := p.Ancestors[len(p.Ancestors)-1]
	if p.document.SelectionsAfterInlineFragment(ref, ancestor) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterFragmentDefinition(ref int) {
	p.write(literal.FRAGMENT)
	p.write(literal.SPACE)
	p.write(p.document.Input.ByteSlice(p.document.FragmentDefinitions[ref].Name))
	p.write(literal.SPACE)
	p.write(literal.ON)
	p.write(literal.SPACE)
	p.write(p.document.Input.ByteSlice(p.document.Types[p.document.FragmentDefinitions[ref].TypeCondition.Type].Name))
	p.write(literal.SPACE)

}

func (p *printVisitor) LeaveFragmentDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindFragmentDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterObjectTypeDefinition(ref int) {

	if p.document.ObjectTypeDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.ObjectTypeDefinitions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.TYPE)
	p.write(literal.SPACE)
	p.write(p.document.ObjectTypeDefinitionNameBytes(ref))
	p.write(literal.SPACE)

	if len(p.document.ObjectTypeDefinitions[ref].ImplementsInterfaces.Refs) != 0 {
		p.write(literal.IMPLEMENTS)
		p.write(literal.SPACE)
		for i, j := range p.document.ObjectTypeDefinitions[ref].ImplementsInterfaces.Refs {
			if i != 0 {
				p.write(literal.SPACE)
				p.write(literal.AND)
				p.write(literal.SPACE)
			}
			p.must(p.document.PrintType(j, p.out))
		}
		p.write(literal.SPACE)
	}

	p.inputValueDefinitionOpener = literal.LPAREN
	p.inputValueDefinitionCloser = literal.RPAREN
}

func (p *printVisitor) LeaveObjectTypeDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindObjectTypeDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterObjectTypeExtension(ref int) {

	if p.document.ObjectTypeExtensions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.ObjectTypeExtensions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.TYPE)
	p.write(literal.SPACE)
	p.write(p.document.ObjectTypeExtensionNameBytes(ref))
	p.write(literal.SPACE)

	p.inputValueDefinitionOpener = literal.LPAREN
	p.inputValueDefinitionCloser = literal.RPAREN
}

func (p *printVisitor) LeaveObjectTypeExtension(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindObjectTypeExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterFieldDefinition(ref int) {
	if p.document.FieldDefinitionIsFirst(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(literal.LBRACE)
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
	}
	if p.document.FieldDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.FieldDefinitions[ref].Description, p.indent, p.indentationDepth(), p.out))
		p.write(literal.LINETERMINATOR)
	}
	p.writeIndented(p.document.FieldDefinitionNameBytes(ref))
}

func (p *printVisitor) LeaveFieldDefinition(ref int) {
	if !p.document.FieldDefinitionHasDirectives(ref) {
		p.writeFieldType(ref)
	}

	if p.document.FieldDefinitionIsLast(ref, p.Ancestors[len(p.Ancestors)-1]) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
		p.write(literal.RBRACE)
	} else {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterInputValueDefinition(ref int) {
	if p.document.InputValueDefinitionIsFirst(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(p.inputValueDefinitionOpener)
	}
	if p.indent != nil {
		switch p.Ancestors[len(p.Ancestors)-1].Kind {
		case ast.NodeKindDirectiveDefinition, ast.NodeKindInputObjectTypeDefinition, ast.NodeKindInputObjectTypeExtension:
			p.write(literal.LINETERMINATOR)
		}
	}
	if p.document.InputValueDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.InputValueDefinitions[ref].Description, p.indent, p.indentationDepth(), p.out))
		p.write(literal.LINETERMINATOR)
	}
	switch p.Ancestors[len(p.Ancestors)-1].Kind {
	case ast.NodeKindDirectiveDefinition, ast.NodeKindInputObjectTypeDefinition, ast.NodeKindInputObjectTypeExtension:
		p.writeIndented(p.document.InputValueDefinitionNameBytes(ref))
	default:
		p.write(p.document.InputValueDefinitionNameBytes(ref))
	}
	p.write(literal.COLON)
	p.write(literal.SPACE)
	p.must(p.document.PrintType(p.document.InputValueDefinitionType(ref), p.out))
	if p.document.InputValueDefinitionHasDefaultValue(ref) {
		p.write(literal.SPACE)
		p.write(literal.EQUALS)
		p.write(literal.SPACE)
		p.must(p.document.PrintValue(p.document.InputValueDefinitionDefaultValue(ref), p.out))
	}
}

func (p *printVisitor) LeaveInputValueDefinition(ref int) {
	if p.document.InputValueDefinitionIsLast(ref, p.Ancestors[len(p.Ancestors)-1]) {
		if p.indent != nil {
			switch p.Ancestors[len(p.Ancestors)-1].Kind {
			case ast.NodeKindDirectiveDefinition, ast.NodeKindInputObjectTypeDefinition, ast.NodeKindInputObjectTypeExtension:
				p.write(literal.LINETERMINATOR)
			}
		}
		p.write(p.inputValueDefinitionCloser)
	} else {
		if len(p.Ancestors) > 0 {
			// check enclosing type kind
			if p.Ancestors[len(p.Ancestors)-1].Kind == ast.NodeKindFieldDefinition {
				p.write(literal.COMMA)
				p.write(literal.SPACE)
			} else if len(p.indent) == 0 {
				// add space between arguments when printing without indents
				p.write(literal.SPACE)
			}
		}
	}
}

func (p *printVisitor) EnterInterfaceTypeDefinition(ref int) {

	if p.document.InterfaceTypeDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.InterfaceTypeDefinitions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.INTERFACE)
	p.write(literal.SPACE)
	p.write(p.document.InterfaceTypeDefinitionNameBytes(ref))
	p.write(literal.SPACE)

	p.inputValueDefinitionOpener = literal.LPAREN
	p.inputValueDefinitionCloser = literal.RPAREN
}

func (p *printVisitor) LeaveInterfaceTypeDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindInterfaceTypeDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterInterfaceTypeExtension(ref int) {

	if p.document.InterfaceTypeExtensions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.InterfaceTypeExtensions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.INTERFACE)
	p.write(literal.SPACE)
	p.write(p.document.InterfaceTypeExtensionNameBytes(ref))
	p.write(literal.SPACE)

	p.inputValueDefinitionOpener = literal.LPAREN
	p.inputValueDefinitionCloser = literal.RPAREN
}

func (p *printVisitor) LeaveInterfaceTypeExtension(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindInterfaceTypeExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterScalarTypeDefinition(ref int) {

	if p.document.ScalarTypeDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.ScalarTypeDefinitions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.SCALAR)
	p.write(literal.SPACE)
	p.write(p.document.ScalarTypeDefinitionNameBytes(ref))
	if p.document.ScalarTypeDefinitionHasDirectives(ref) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveScalarTypeDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindScalarTypeDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterScalarTypeExtension(ref int) {

	if p.document.ScalarTypeExtensions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.ScalarTypeExtensions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.SCALAR)
	p.write(literal.SPACE)
	p.write(p.document.ScalarTypeExtensionNameBytes(ref))
	if p.document.ScalarTypeExtensionHasDirectives(ref) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveScalarTypeExtension(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindScalarTypeExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterUnionTypeDefinition(ref int) {

	if p.document.UnionTypeDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.UnionTypeDefinitions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.UNION)
	p.write(literal.SPACE)
	p.write(p.document.UnionTypeDefinitionNameBytes(ref))
	if p.document.UnionTypeDefinitionHasDirectives(ref) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveUnionTypeDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindUnionTypeDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterUnionTypeExtension(ref int) {

	if p.document.UnionTypeExtensions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.UnionTypeExtensions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.UNION)
	p.write(literal.SPACE)
	p.write(p.document.UnionTypeExtensionNameBytes(ref))
	if p.document.UnionTypeExtensionHasDirectives(ref) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveUnionTypeExtension(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindUnionTypeExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterUnionMemberType(ref int) {
	if p.document.UnionMemberTypeIsFirst(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(literal.SPACE)
		p.write(literal.EQUALS)
		p.write(literal.SPACE)
	}
	p.write(p.document.TypeNameBytes(ref))
	if !p.document.UnionMemberTypeIsLast(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(literal.SPACE)
		p.write(literal.PIPE)
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveUnionMemberType(ref int) {

}

func (p *printVisitor) EnterEnumTypeDefinition(ref int) {

	if p.document.EnumTypeDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.EnumTypeDefinitions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.ENUM)
	p.write(literal.SPACE)
	p.write(p.document.EnumTypeDefinitionNameBytes(ref))
	if p.document.EnumTypeDefinitionHasDirectives(ref) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveEnumTypeDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindEnumTypeDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterEnumTypeExtension(ref int) {

	if p.document.EnumTypeExtensions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.EnumTypeExtensions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.ENUM)
	p.write(literal.SPACE)
	p.write(p.document.EnumTypeExtensionNameBytes(ref))
	if p.document.EnumTypeExtensionHasDirectives(ref) {
		p.write(literal.SPACE)
	}
}

func (p *printVisitor) LeaveEnumTypeExtension(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindEnumTypeExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterEnumValueDefinition(ref int) {
	if p.document.EnumValueDefinitionIsFirst(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(literal.SPACE)
		p.write(literal.LBRACE)
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
	}
	if p.document.EnumValueDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.EnumValueDefinitions[ref].Description, p.indent, p.indentationDepth(), p.out))
		p.write(literal.LINETERMINATOR)
	}
	p.writeIndented(p.document.EnumValueDefinitionNameBytes(ref))
}

func (p *printVisitor) LeaveEnumValueDefinition(ref int) {
	if p.document.EnumValueDefinitionIsLast(ref, p.Ancestors[len(p.Ancestors)-1]) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
		p.write(literal.RBRACE)
	} else {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterInputObjectTypeDefinition(ref int) {

	if p.document.InputObjectTypeDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.InputObjectTypeDefinitions[ref].Description, nil, 0, p.out))
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
	}

	p.write(literal.INPUT)
	p.write(literal.SPACE)
	p.write(p.document.InputObjectTypeDefinitionNameBytes(ref))
	p.write(literal.SPACE)

	p.inputValueDefinitionOpener = literal.LBRACE
	p.inputValueDefinitionCloser = literal.RBRACE
}

func (p *printVisitor) LeaveInputObjectTypeDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindInputObjectTypeDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterInputObjectTypeExtension(ref int) {

	if p.document.InputObjectTypeExtensions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.InputObjectTypeExtensions[ref].Description, nil, 0, p.out))
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
	}

	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.INPUT)
	p.write(literal.SPACE)
	p.write(p.document.InputObjectTypeExtensionNameBytes(ref))
	p.write(literal.SPACE)

	p.inputValueDefinitionOpener = literal.LBRACE
	p.inputValueDefinitionCloser = literal.RBRACE
}

func (p *printVisitor) LeaveInputObjectTypeExtension(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindInputObjectTypeExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterDirectiveDefinition(ref int) {

	if p.document.DirectiveDefinitions[ref].Description.IsDefined {
		p.must(p.document.PrintDescription(p.document.DirectiveDefinitions[ref].Description, nil, 0, p.out))
		p.write(literal.LINETERMINATOR)
	}

	p.write(literal.DIRECTIVE)
	p.write(literal.SPACE)
	p.write(literal.AT)
	p.write(p.document.DirectiveDefinitionNameBytes(ref))
	p.isFirstDirectiveLocation = true

	p.inputValueDefinitionOpener = literal.LPAREN
	p.inputValueDefinitionCloser = literal.RPAREN
}

func (p *printVisitor) LeaveDirectiveDefinition(ref int) {
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindDirectiveDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterDirectiveLocation(location ast.DirectiveLocation) {

	if p.isFirstDirectiveLocation {
		p.isFirstDirectiveLocation = false
		p.write(literal.SPACE)
		p.write(literal.ON)
		p.write(literal.SPACE)
	} else {
		p.write(literal.SPACE)
		p.write(literal.PIPE)
		p.write(literal.SPACE)
	}

	switch location {
	case ast.ExecutableDirectiveLocationQuery:
		p.write(literal.LocationQuery)
	case ast.ExecutableDirectiveLocationMutation:
		p.write(literal.LocationMutation)
	case ast.ExecutableDirectiveLocationSubscription:
		p.write(literal.LocationSubscription)
	case ast.ExecutableDirectiveLocationField:
		p.write(literal.LocationField)
	case ast.ExecutableDirectiveLocationFragmentDefinition:
		p.write(literal.LocationFragmentDefinition)
	case ast.ExecutableDirectiveLocationFragmentSpread:
		p.write(literal.LocationFragmentSpread)
	case ast.ExecutableDirectiveLocationInlineFragment:
		p.write(literal.LocationInlineFragment)
	case ast.ExecutableDirectiveLocationVariableDefinition:
		p.write(literal.LocationVariableDefinition)
	case ast.TypeSystemDirectiveLocationSchema:
		p.write(literal.LocationSchema)
	case ast.TypeSystemDirectiveLocationScalar:
		p.write(literal.LocationScalar)
	case ast.TypeSystemDirectiveLocationObject:
		p.write(literal.LocationObject)
	case ast.TypeSystemDirectiveLocationFieldDefinition:
		p.write(literal.LocationFieldDefinition)
	case ast.TypeSystemDirectiveLocationArgumentDefinition:
		p.write(literal.LocationArgumentDefinition)
	case ast.TypeSystemDirectiveLocationInterface:
		p.write(literal.LocationInterface)
	case ast.TypeSystemDirectiveLocationUnion:
		p.write(literal.LocationUnion)
	case ast.TypeSystemDirectiveLocationEnum:
		p.write(literal.LocationEnum)
	case ast.TypeSystemDirectiveLocationEnumValue:
		p.write(literal.LocationEnumValue)
	case ast.TypeSystemDirectiveLocationInputObject:
		p.write(literal.LocationInputObject)
	case ast.TypeSystemDirectiveLocationInputFieldDefinition:
		p.write(literal.LocationInputFieldDefinition)
	}
}

func (p *printVisitor) LeaveDirectiveLocation(location ast.DirectiveLocation) {

}

func (p *printVisitor) EnterSchemaDefinition(ref int) {
	p.write(literal.SCHEMA)
	p.write(literal.SPACE)
}

func (p *printVisitor) LeaveSchemaDefinition(ref int) {
	if p.indent != nil {
		p.write(literal.LINETERMINATOR)
	}
	p.write(literal.RBRACE)
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindSchemaDefinition, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterSchemaExtension(ref int) {
	p.write(literal.EXTEND)
	p.write(literal.SPACE)
	p.write(literal.SCHEMA)
	p.write(literal.SPACE)
}

func (p *printVisitor) LeaveSchemaExtension(ref int) {
	if p.indent != nil {
		p.write(literal.LINETERMINATOR)
	}
	p.write(literal.RBRACE)
	if !p.document.NodeIsLastRootNode(ast.Node{Kind: ast.NodeKindSchemaExtension, Ref: ref}) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterRootOperationTypeDefinition(ref int) {
	if p.document.RootOperationTypeDefinitionIsFirstInSchemaDefinition(ref, p.Ancestors[len(p.Ancestors)-1]) {
		p.write(literal.LBRACE)
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		}
	}
	switch p.document.RootOperationTypeDefinitions[ref].OperationType {
	case ast.OperationTypeQuery:
		p.writeIndented(literal.QUERY)
	case ast.OperationTypeMutation:
		p.writeIndented(literal.MUTATION)
	case ast.OperationTypeSubscription:
		p.writeIndented(literal.SUBSCRIPTION)
	}
	p.write(literal.COLON)
	p.write(literal.SPACE)
	p.write(p.document.Input.ByteSlice(p.document.RootOperationTypeDefinitions[ref].NamedType.Name))
}

func (p *printVisitor) LeaveRootOperationTypeDefinition(ref int) {
	if !p.document.RootOperationTypeDefinitionIsLastInSchemaDefinition(ref, p.Ancestors[len(p.Ancestors)-1]) {
		if p.indent != nil {
			p.write(literal.LINETERMINATOR)
		} else {
			p.write(literal.SPACE)
		}
	}
}

func (p *printVisitor) EnterDocument(operation, definition *ast.Document) {

}

func (p *printVisitor) LeaveDocument(operation, definition *ast.Document) {

}

func (p *printVisitor) writeFieldType(ref int) {
	p.write(literal.COLON)
	p.write(literal.SPACE)
	p.must(p.document.PrintType(p.document.FieldDefinitionType(ref), p.out))
}
