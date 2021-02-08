// Package astparser is used to turn raw GraphQL documents into an AST.
package astparser

import (
	"fmt"
	"runtime"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/identkeyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/keyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/token"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// ParseGraphqlDocumentString takes a raw GraphQL document in string format and parses it into an AST.
// This function creates a new parser as well as a new AST for every call.
// Therefore you shouldn't use this function in a hot path.
// Instead create a parser as well as AST objects and re-use them.
func ParseGraphqlDocumentString(input string) (ast.Document, operationreport.Report) {
	return ParseGraphqlDocumentBytes([]byte(input))
}

// ParseGraphqlDocumentBytes takes a raw GraphQL document in byte slice format and parses it into an AST.
// This function creates a new parser as well as a new AST for every call.
// Therefore you shouldn't use this function in a hot path.
// Instead create a parser as well as AST objects and re-use them.
func ParseGraphqlDocumentBytes(input []byte) (ast.Document, operationreport.Report) {
	parser := NewParser()
	doc := *ast.NewDocument()
	doc.Input.ResetInputBytes(input)
	report := operationreport.Report{}
	parser.Parse(&doc, &report)
	return doc, report
}

type origin struct {
	file     string
	line     int
	funcName string
}

// ErrUnexpectedToken is a custom error object containing all necessary information to properly render an unexpected token error
type ErrUnexpectedToken struct {
	keyword  keyword.Keyword
	expected []keyword.Keyword
	position position.Position
	literal  string
	origins  []origin
}

func (e ErrUnexpectedToken) Error() string {

	origins := ""
	for _, origin := range e.origins {
		origins = origins + fmt.Sprintf("\n\t\t%s:%d\n\t\t%s", origin.file, origin.line, origin.funcName)
	}

	return fmt.Sprintf("unexpected token - keyword: '%s' literal: '%s' - expected: '%s' position: '%s'%s", e.keyword, e.literal, e.expected, e.position, origins)
}

// ErrUnexpectedIdentKey is a custom error object to properly render an unexpected ident key error
type ErrUnexpectedIdentKey struct {
	keyword  identkeyword.IdentKeyword
	expected []identkeyword.IdentKeyword
	position position.Position
	literal  string
	origins  []origin
}

func (e ErrUnexpectedIdentKey) Error() string {

	origins := ""
	for _, origin := range e.origins {
		origins = origins + fmt.Sprintf("\n\t\t%s:%d\n\t\t%s", origin.file, origin.line, origin.funcName)
	}

	return fmt.Sprintf("unexpected ident - keyword: '%s' literal: '%s' - expected: '%s' position: '%s'%s", e.keyword, e.literal, e.expected, e.position, origins)
}

// Parser takes a raw input and turns it into an AST
// use NewParser() to create a parser
// Don't create new parsers in the hot path, re-use them.
type Parser struct {
	document             *ast.Document
	report               *operationreport.Report
	lexer                *lexer.Lexer
	tokens               []token.Token
	maxTokens            int
	currentToken         int
	shouldIndex          bool
	reportInternalErrors bool
}

// NewParser returns a new parser with all values properly initialized
func NewParser() *Parser {
	return &Parser{
		tokens:               make([]token.Token, 256),
		lexer:                &lexer.Lexer{},
		shouldIndex:          true,
		reportInternalErrors: false,
	}
}

// PrepareImport prepares the Parser for importing new Nodes into an AST without directly parsing the content
func (p *Parser) PrepareImport(document *ast.Document, report *operationreport.Report) {
	p.document = document
	p.report = report
	p.lexer.SetInput(&document.Input)
	p.tokenize()
}

// Parse parses all input in a Document.Input into the Document
func (p *Parser) Parse(document *ast.Document, report *operationreport.Report) {
	p.document = document
	p.report = report
	p.lexer.SetInput(&document.Input)
	p.tokenize()
	p.parse()
}

func (p *Parser) tokenize() {

	p.tokens = p.tokens[:0]

	for {
		next := p.lexer.Read()
		if next.Keyword == keyword.EOF {
			p.maxTokens = len(p.tokens)
			p.currentToken = -1
			return
		}
		p.tokens = append(p.tokens, next)
	}
}

func (p *Parser) parse() {
	for {
		key, literalReference := p.peekLiteral()

		switch key {
		case keyword.EOF:
			p.read()
			return
		case keyword.LBRACE:
			p.parseOperationDefinition()
		case keyword.COMMENT:
			p.read()
		case keyword.STRING, keyword.BLOCKSTRING:
			p.parseRootDescription()
		case keyword.IDENT:
			keyIdent := p.identKeywordSliceRef(literalReference)
			switch keyIdent {
			case identkeyword.ENUM:
				p.parseEnumTypeDefinition(nil)
			case identkeyword.TYPE:
				p.parseObjectTypeDefinition(nil)
			case identkeyword.UNION:
				p.parseUnionTypeDefinition(nil)
			case identkeyword.QUERY, identkeyword.MUTATION, identkeyword.SUBSCRIPTION:
				p.parseOperationDefinition()
			case identkeyword.INPUT:
				p.parseInputObjectTypeDefinition(nil)
			case identkeyword.EXTEND:
				p.parseExtension()
			case identkeyword.SCHEMA:
				p.parseSchemaDefinition()
			case identkeyword.SCALAR:
				p.parseScalarTypeDefinition(nil)
			case identkeyword.FRAGMENT:
				p.parseFragmentDefinition()
			case identkeyword.INTERFACE:
				p.parseInterfaceTypeDefinition(nil)
			case identkeyword.DIRECTIVE:
				p.parseDirectiveDefinition(nil)
			default:
				p.errUnexpectedIdentKey(p.read(), keyIdent, identkeyword.ENUM, identkeyword.TYPE, identkeyword.UNION, identkeyword.QUERY, identkeyword.INPUT, identkeyword.EXTEND, identkeyword.SCHEMA, identkeyword.SCALAR, identkeyword.FRAGMENT, identkeyword.INTERFACE, identkeyword.DIRECTIVE)
			}
		default:
			p.errUnexpectedToken(p.read(), keyword.EOF, keyword.LBRACE, keyword.COMMENT, keyword.STRING, keyword.BLOCKSTRING, keyword.IDENT)
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) next() int {
	if p.currentToken != p.maxTokens-1 {
		p.currentToken++
	}
	return p.currentToken
}

func (p *Parser) read() token.Token {
	p.currentToken++
	if p.currentToken < p.maxTokens {
		return p.tokens[p.currentToken]
	}

	return token.Token{
		Keyword: keyword.EOF,
	}
}

func (p *Parser) identKeywordToken(token token.Token) identkeyword.IdentKeyword {
	return identkeyword.KeywordFromLiteral(p.document.Input.ByteSlice(token.Literal))
}

func (p *Parser) identKeywordSliceRef(ref ast.ByteSliceReference) identkeyword.IdentKeyword {
	return identkeyword.KeywordFromLiteral(p.document.Input.ByteSlice(ref))
}

func (p *Parser) readExpectLiteral(expect ...identkeyword.IdentKeyword) (token.Token, identkeyword.IdentKeyword) {
	p.currentToken++
	if p.currentToken < p.maxTokens {
		out := p.tokens[p.currentToken]
		identKey := p.identKeywordToken(out)
		for _, expectation := range expect {
			if identKey == expectation {
				return out, identKey
			}
		}
		p.errUnexpectedToken(out)
		return out, identKey
	}

	return token.Token{
		Keyword: keyword.EOF,
	}, identkeyword.UNDEFINED
}

func (p *Parser) peek() keyword.Keyword {
	nextIndex := p.currentToken + 1
	if nextIndex < p.maxTokens {
		return p.tokens[nextIndex].Keyword
	}
	return keyword.EOF
}

func (p *Parser) peekLiteral() (keyword.Keyword, ast.ByteSliceReference) {
	nextIndex := p.currentToken + 1
	if nextIndex < p.maxTokens {
		return p.tokens[nextIndex].Keyword, p.tokens[nextIndex].Literal
	}
	return keyword.EOF, ast.ByteSliceReference{}
}

func (p *Parser) peekEquals(key keyword.Keyword) bool {
	return p.peek() == key
}

func (p *Parser) peekEqualsIdentKey(identKey identkeyword.IdentKeyword) bool {
	key, literal := p.peekLiteral()
	if key != keyword.IDENT {
		return false
	}
	actualKey := p.identKeywordSliceRef(literal)
	return actualKey == identKey
}

func (p *Parser) errUnexpectedIdentKey(unexpected token.Token, unexpectedKey identkeyword.IdentKeyword, expectedKeywords ...identkeyword.IdentKeyword) {

	if p.report.HasErrors() {
		return
	}

	p.report.AddExternalError(operationreport.ExternalError{
		Message: fmt.Sprintf("unexpected literal - got: %s want one of: %v", unexpectedKey, expectedKeywords),
		Locations: []operationreport.Location{
			{
				Line:   unexpected.TextPosition.LineStart,
				Column: unexpected.TextPosition.CharStart,
			},
		},
	})

	if !p.reportInternalErrors {
		return
	}

	origins := make([]origin, 3)
	for i := range origins {
		fpcs := make([]uintptr, 1)
		callers := runtime.Callers(2+i, fpcs)

		if callers == 0 {
			origins = origins[:i]
			break
		}

		fn := runtime.FuncForPC(fpcs[0])
		file, line := fn.FileLine(fpcs[0])

		origins[i].file = file
		origins[i].line = line
		origins[i].funcName = fn.Name()
	}

	p.report.AddInternalError(ErrUnexpectedIdentKey{
		keyword:  unexpectedKey,
		position: unexpected.TextPosition,
		literal:  p.document.Input.ByteSliceString(unexpected.Literal),
		origins:  origins,
		expected: expectedKeywords,
	})
}

func (p *Parser) errUnexpectedToken(unexpected token.Token, expectedKeywords ...keyword.Keyword) {

	if p.report.HasErrors() {
		return
	}

	p.report.AddExternalError(operationreport.ExternalError{
		Message: fmt.Sprintf("unexpected token - got: %s want one of: %v", unexpected.Keyword, expectedKeywords),
		Locations: []operationreport.Location{
			{
				Line:   unexpected.TextPosition.LineStart,
				Column: unexpected.TextPosition.CharStart,
			},
		},
	})

	if !p.reportInternalErrors {
		return
	}

	origins := make([]origin, 3)
	for i := range origins {
		fpcs := make([]uintptr, 1)
		callers := runtime.Callers(2+i, fpcs)

		if callers == 0 {
			origins = origins[:i]
			break
		}

		fn := runtime.FuncForPC(fpcs[0])
		file, line := fn.FileLine(fpcs[0])

		origins[i].file = file
		origins[i].line = line
		origins[i].funcName = fn.Name()
	}

	p.report.AddInternalError(ErrUnexpectedToken{
		keyword:  unexpected.Keyword,
		position: unexpected.TextPosition,
		literal:  p.document.Input.ByteSliceString(unexpected.Literal),
		origins:  origins,
		expected: expectedKeywords,
	})
}

func (p *Parser) mustNext(key keyword.Keyword) int {
	current := p.currentToken
	if p.next() == current {
		p.errUnexpectedToken(p.tokens[p.currentToken], key)
		return p.currentToken
	}
	if p.tokens[p.currentToken].Keyword != key {
		p.errUnexpectedToken(p.tokens[p.currentToken], key)
		return p.currentToken
	}
	return p.currentToken
}

func (p *Parser) mustRead(key keyword.Keyword) (next token.Token) {
	next = p.read()
	if next.Keyword != key {
		p.errUnexpectedToken(next, key)
	}
	return
}

func (p *Parser) mustReadIdentKey(key identkeyword.IdentKeyword) (next token.Token) {
	next = p.read()
	if next.Keyword != keyword.IDENT {
		p.errUnexpectedToken(next, keyword.IDENT)
	}
	identKey := p.identKeywordToken(next)
	if identKey != key {
		p.errUnexpectedIdentKey(next, identKey, key)
	}
	return
}

func (p *Parser) mustReadExceptIdentKey(key identkeyword.IdentKeyword) (next token.Token) {
	next = p.read()
	if next.Keyword != keyword.IDENT {
		p.errUnexpectedToken(next, keyword.IDENT)
	}
	identKey := p.identKeywordToken(next)
	if identKey == key {
		p.errUnexpectedIdentKey(next, identKey, key)
	}
	return
}

func (p *Parser) parseSchemaDefinition() {

	schemaLiteral := p.read()

	schemaDefinition := ast.SchemaDefinition{
		SchemaLiteral: schemaLiteral.TextPosition,
	}

	if p.peekEquals(keyword.AT) {
		schemaDefinition.Directives = p.parseDirectiveList()
		schemaDefinition.HasDirectives = len(schemaDefinition.Directives.Refs) > 0
	}

	p.parseRootOperationTypeDefinitionList(&schemaDefinition.RootOperationTypeDefinitions)

	p.document.SchemaDefinitions = append(p.document.SchemaDefinitions, schemaDefinition)

	ref := len(p.document.SchemaDefinitions) - 1
	rootNode := ast.Node{
		Kind: ast.NodeKindSchemaDefinition,
		Ref:  ref,
	}
	p.document.RootNodes = append(p.document.RootNodes, rootNode)
}

func (p *Parser) parseRootOperationTypeDefinitionList(list *ast.RootOperationTypeDefinitionList) {

	curlyBracketOpen := p.mustRead(keyword.LBRACE)

	for {
		next := p.peek()
		switch next {
		case keyword.RBRACE:

			curlyBracketClose := p.read()
			list.LBrace = curlyBracketOpen.TextPosition
			list.RBrace = curlyBracketClose.TextPosition
			return
		case keyword.IDENT:

			_, operationType := p.readExpectLiteral(identkeyword.QUERY, identkeyword.MUTATION, identkeyword.SUBSCRIPTION)
			colon := p.mustRead(keyword.COLON)
			namedType := p.mustRead(keyword.IDENT)

			rootOperationTypeDefinition := ast.RootOperationTypeDefinition{
				OperationType: p.operationTypeFromIdentKeyword(operationType),
				Colon:         colon.TextPosition,
				NamedType: ast.Type{
					TypeKind: ast.TypeKindNamed,
					Name:     namedType.Literal,
				},
			}

			p.document.RootOperationTypeDefinitions = append(p.document.RootOperationTypeDefinitions, rootOperationTypeDefinition)
			ref := len(p.document.RootOperationTypeDefinitions) - 1

			if cap(list.Refs) == 0 {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}

			list.Refs = append(list.Refs, ref)

			if p.shouldIndex {
				p.indexRootOperationTypeDefinition(rootOperationTypeDefinition)
			}

		default:
			p.errUnexpectedToken(p.read())
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) indexRootOperationTypeDefinition(definition ast.RootOperationTypeDefinition) {
	switch definition.OperationType {
	case ast.OperationTypeQuery:
		p.document.Index.QueryTypeName = p.document.Input.ByteSlice(definition.NamedType.Name)
	case ast.OperationTypeMutation:
		p.document.Index.MutationTypeName = p.document.Input.ByteSlice(definition.NamedType.Name)
	case ast.OperationTypeSubscription:
		p.document.Index.SubscriptionTypeName = p.document.Input.ByteSlice(definition.NamedType.Name)
	}
}

func (p *Parser) operationTypeFromIdentKeyword(key identkeyword.IdentKeyword) ast.OperationType {
	switch key {
	case identkeyword.QUERY:
		return ast.OperationTypeQuery
	case identkeyword.MUTATION:
		return ast.OperationTypeMutation
	case identkeyword.SUBSCRIPTION:
		return ast.OperationTypeSubscription
	default:
		return ast.OperationTypeUnknown
	}
}

func (p *Parser) parseDirectiveList() (list ast.DirectiveList) {

	for {

		if p.peek() != keyword.AT {
			break
		}

		at := p.read()
		name := p.mustRead(keyword.IDENT)

		directive := ast.Directive{
			At:   at.TextPosition,
			Name: name.Literal,
		}

		if p.peekEquals(keyword.LPAREN) {
			directive.Arguments = p.parseArgumentList()
			directive.HasArguments = len(directive.Arguments.Refs) > 0
		}

		p.document.Directives = append(p.document.Directives, directive)
		ref := len(p.document.Directives) - 1

		if cap(list.Refs) == 0 {
			list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
		}

		list.Refs = append(list.Refs, ref)

		if p.report.HasErrors() {
			return
		}
	}

	return
}

func (p *Parser) parseArgumentList() (list ast.ArgumentList) {

	bracketOpen := p.next()

Loop:
	for {

		next := p.peek()
		switch next {
		case keyword.IDENT:
		default:
			break Loop
		}

		name := p.next()
		colon := p.mustRead(keyword.COLON)
		value := p.ParseValue()

		argument := ast.Argument{
			Name:  p.tokens[name].Literal,
			Colon: colon.TextPosition,
			Value: value,
		}

		p.document.Arguments = append(p.document.Arguments, argument)
		ref := len(p.document.Arguments) - 1

		if cap(list.Refs) == 0 {
			list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
		}

		list.Refs = append(list.Refs, ref)

		if p.report.HasErrors() {
			return
		}
	}

	bracketClose := p.mustRead(keyword.RPAREN)

	list.LPAREN = p.tokens[bracketOpen].TextPosition
	list.RPAREN = bracketClose.TextPosition

	return
}

func (p *Parser) ParseValue() (value ast.Value) {

	next, literal := p.peekLiteral()

	switch next {
	case keyword.STRING, keyword.BLOCKSTRING:
		value.Kind = ast.ValueKindString
		value.Ref = p.parseStringValue()
	case keyword.IDENT:
		key := p.identKeywordSliceRef(literal)
		switch key {
		case identkeyword.TRUE, identkeyword.FALSE:
			value.Kind = ast.ValueKindBoolean
			value.Ref = p.parseBooleanValue()
		case identkeyword.NULL:
			value.Kind = ast.ValueKindNull
			p.read()
		default:
			value.Kind = ast.ValueKindEnum
			value.Ref = p.parseEnumValue()
		}
	case keyword.DOLLAR:
		value.Kind = ast.ValueKindVariable
		value.Ref = p.parseVariableValue()
	case keyword.INTEGER:
		value.Kind = ast.ValueKindInteger
		value.Ref = p.parseIntegerValue(nil)
	case keyword.FLOAT:
		value.Kind = ast.ValueKindFloat
		value.Ref = p.parseFloatValue(nil)
	case keyword.SUB:
		value = p.parseNegativeNumberValue()
	case keyword.LBRACK:
		value.Kind = ast.ValueKindList
		value.Ref = p.parseValueList()
	case keyword.LBRACE:
		value.Kind = ast.ValueKindObject
		value.Ref = p.parseObjectValue()
	default:
		p.errUnexpectedToken(p.read())
	}

	return
}

func (p *Parser) parseObjectValue() int {
	var objectValue ast.ObjectValue
	objectValue.LBRACE = p.mustRead(keyword.LBRACE).TextPosition

	for {
		next := p.peek()
		switch next {
		case keyword.RBRACE:
			objectValue.RBRACE = p.read().TextPosition
			p.document.ObjectValues = append(p.document.ObjectValues, objectValue)
			return len(p.document.ObjectValues) - 1
		case keyword.IDENT:
			ref := p.parseObjectField()
			if cap(objectValue.Refs) == 0 {
				objectValue.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			objectValue.Refs = append(objectValue.Refs, ref)
		default:
			p.errUnexpectedToken(p.read(), keyword.IDENT, keyword.RBRACE)
			return -1
		}

		if p.report.HasErrors() {
			return -1
		}
	}
}

func (p *Parser) parseObjectField() int {
	objectField := ast.ObjectField{
		Name:  p.mustRead(keyword.IDENT).Literal,
		Colon: p.mustRead(keyword.COLON).TextPosition,
		Value: p.ParseValue(),
	}
	p.document.ObjectFields = append(p.document.ObjectFields, objectField)
	return len(p.document.ObjectFields) - 1
}

func (p *Parser) parseValueList() int {
	var list ast.ListValue
	list.LBRACK = p.mustRead(keyword.LBRACK).TextPosition

	for {
		next := p.peek()
		switch next {
		case keyword.RBRACK:
			list.RBRACK = p.read().TextPosition
			p.document.ListValues = append(p.document.ListValues, list)
			return len(p.document.ListValues) - 1
		default:
			value := p.ParseValue()
			p.document.Values = append(p.document.Values, value)
			ref := len(p.document.Values) - 1
			if cap(list.Refs) == 0 {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			list.Refs = append(list.Refs, ref)
		}

		if p.report.HasErrors() {
			return -1
		}
	}
}

func (p *Parser) parseNegativeNumberValue() (value ast.Value) {
	negativeSign := p.mustRead(keyword.SUB).TextPosition
	switch p.peek() {
	case keyword.INTEGER:
		value.Kind = ast.ValueKindInteger
		value.Ref = p.parseIntegerValue(&negativeSign)
	case keyword.FLOAT:
		value.Kind = ast.ValueKindFloat
		value.Ref = p.parseFloatValue(&negativeSign)
	default:
		p.errUnexpectedToken(p.read(), keyword.INTEGER, keyword.FLOAT)
	}

	return
}

func (p *Parser) parseFloatValue(negativeSign *position.Position) int {

	value := p.mustRead(keyword.FLOAT)

	if negativeSign != nil && negativeSign.CharEnd != value.TextPosition.CharStart {
		p.errUnexpectedToken(value)
		return -1
	}

	floatValue := ast.FloatValue{
		Raw: value.Literal,
	}
	if negativeSign != nil {
		floatValue.Negative = true
		floatValue.NegativeSign = *negativeSign
	}

	p.document.FloatValues = append(p.document.FloatValues, floatValue)
	return len(p.document.FloatValues) - 1
}

func (p *Parser) parseIntegerValue(negativeSign *position.Position) int {

	value := p.mustRead(keyword.INTEGER)

	if negativeSign != nil && negativeSign.CharEnd != value.TextPosition.CharStart {
		p.errUnexpectedToken(value)
		return -1
	}

	intValue := ast.IntValue{
		Raw: value.Literal,
	}
	if negativeSign != nil {
		intValue.Negative = true
		intValue.NegativeSign = *negativeSign
	}

	p.document.IntValues = append(p.document.IntValues, intValue)
	return len(p.document.IntValues) - 1
}

func (p *Parser) parseVariableValue() int {
	dollar := p.mustRead(keyword.DOLLAR)
	var value token.Token

	next := p.peek()
	switch next {
	case keyword.IDENT:
		value = p.read()
	default:
		p.errUnexpectedToken(p.read(), keyword.IDENT)
		return -1
	}

	if dollar.TextPosition.CharEnd != value.TextPosition.CharStart {
		p.errUnexpectedToken(p.read(), keyword.IDENT)
		return -1
	}

	variable := ast.VariableValue{
		Dollar: dollar.TextPosition,
		Name:   value.Literal,
	}

	p.document.VariableValues = append(p.document.VariableValues, variable)
	return len(p.document.VariableValues) - 1
}

func (p *Parser) parseBooleanValue() int {
	value := p.read()
	identKey := p.identKeywordToken(value)
	switch identKey {
	case identkeyword.FALSE:
		return 0
	case identkeyword.TRUE:
		return 1
	default:
		p.errUnexpectedIdentKey(value, identKey, identkeyword.TRUE, identkeyword.FALSE)
		return -1
	}
}

func (p *Parser) parseEnumValue() int {
	enum := ast.EnumValue{
		Name: p.mustRead(keyword.IDENT).Literal,
	}
	p.document.EnumValues = append(p.document.EnumValues, enum)
	return len(p.document.EnumValues) - 1
}

func (p *Parser) parseStringValue() int {
	value := p.read()
	if value.Keyword != keyword.STRING && value.Keyword != keyword.BLOCKSTRING {
		p.errUnexpectedToken(value, keyword.STRING, keyword.BLOCKSTRING)
		return -1
	}
	stringValue := ast.StringValue{
		Content:     value.Literal,
		BlockString: value.Keyword == keyword.BLOCKSTRING,
	}
	p.document.StringValues = append(p.document.StringValues, stringValue)
	return len(p.document.StringValues) - 1
}

func (p *Parser) parseObjectTypeDefinition(description *ast.Description) {
	var objectTypeDefinition ast.ObjectTypeDefinition
	if description != nil {
		objectTypeDefinition.Description = *description
	}
	objectTypeDefinition.TypeLiteral = p.mustReadIdentKey(identkeyword.TYPE).TextPosition
	objectTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEqualsIdentKey(identkeyword.IMPLEMENTS) {
		objectTypeDefinition.ImplementsInterfaces = p.parseImplementsInterfaces()
	}
	if p.peekEquals(keyword.AT) {
		objectTypeDefinition.Directives = p.parseDirectiveList()
		objectTypeDefinition.HasDirectives = len(objectTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		objectTypeDefinition.FieldsDefinition = p.parseFieldDefinitionList()
		objectTypeDefinition.HasFieldDefinitions = len(objectTypeDefinition.FieldsDefinition.Refs) > 0
	}
	p.document.ObjectTypeDefinitions = append(p.document.ObjectTypeDefinitions, objectTypeDefinition)
	ref := len(p.document.ObjectTypeDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindObjectTypeDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(objectTypeDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) indexNode(key ast.ByteSliceReference, value ast.Node) {
	name := p.document.Input.ByteSlice(key)
	p.document.Index.AddNodeBytes(name, value)
}

func (p *Parser) parseRootDescription() {

	description := p.parseDescription()

	key, literal := p.peekLiteral()
	if key != keyword.IDENT {
		p.errUnexpectedToken(p.read(), keyword.IDENT)
		return
	}

	next := p.identKeywordSliceRef(literal)

	switch next {
	case identkeyword.TYPE:
		p.parseObjectTypeDefinition(&description)
	case identkeyword.INPUT:
		p.parseInputObjectTypeDefinition(&description)
	case identkeyword.SCALAR:
		p.parseScalarTypeDefinition(&description)
	case identkeyword.INTERFACE:
		p.parseInterfaceTypeDefinition(&description)
	case identkeyword.UNION:
		p.parseUnionTypeDefinition(&description)
	case identkeyword.ENUM:
		p.parseEnumTypeDefinition(&description)
	case identkeyword.DIRECTIVE:
		p.parseDirectiveDefinition(&description)
	default:
		p.errUnexpectedIdentKey(p.read(), next, identkeyword.TYPE, identkeyword.INPUT, identkeyword.SCALAR, identkeyword.INTERFACE, identkeyword.UNION, identkeyword.ENUM, identkeyword.DIRECTIVE)
	}
}

func (p *Parser) parseImplementsInterfaces() (list ast.TypeList) {

	p.read() // implements

	acceptIdent := true
	acceptAnd := true

	for {
		next := p.peek()
		switch next {
		case keyword.AND:
			if acceptAnd {
				acceptAnd = false
				acceptIdent = true
				p.read()
			} else {
				p.errUnexpectedToken(p.read())
				return
			}
		case keyword.IDENT:
			if acceptIdent {
				acceptIdent = false
				acceptAnd = true
				name := p.read()
				astType := ast.Type{
					TypeKind: ast.TypeKindNamed,
					Name:     name.Literal,
				}
				p.document.Types = append(p.document.Types, astType)
				ref := len(p.document.Types) - 1
				if cap(list.Refs) == 0 {
					list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
				}
				list.Refs = append(list.Refs, ref)
			} else {
				p.errUnexpectedToken(p.read())
				return
			}
		default:
			if acceptIdent {
				p.errUnexpectedToken(p.read())
			}
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseFieldDefinitionList() (list ast.FieldDefinitionList) {

	list.LBRACE = p.mustRead(keyword.LBRACE).TextPosition

	refsInitialized := false

	for {

		next := p.peek()

		switch next {
		case keyword.RBRACE:
			list.RBRACE = p.read().TextPosition
			return
		case keyword.STRING, keyword.BLOCKSTRING, keyword.IDENT:
			ref := p.parseFieldDefinition()
			if !refsInitialized {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
				refsInitialized = true
			}
			list.Refs = append(list.Refs, ref)
		default:
			p.errUnexpectedToken(p.read())
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseFieldDefinition() int {

	var fieldDefinition ast.FieldDefinition

	name := p.peek()
	switch name {
	case keyword.STRING, keyword.BLOCKSTRING:
		fieldDefinition.Description = p.parseDescription()
	case keyword.IDENT:
		break
	default:
		p.errUnexpectedToken(p.read())
		return -1
	}

	nameToken := p.read()
	if nameToken.Keyword != keyword.IDENT {
		p.errUnexpectedToken(nameToken, keyword.IDENT)
		return -1
	}

	fieldDefinition.Name = nameToken.Literal
	if p.peekEquals(keyword.LPAREN) {
		fieldDefinition.ArgumentsDefinition = p.parseInputValueDefinitionList(keyword.RPAREN)
		fieldDefinition.HasArgumentsDefinitions = len(fieldDefinition.ArgumentsDefinition.Refs) > 0
	}
	fieldDefinition.Colon = p.mustRead(keyword.COLON).TextPosition
	fieldDefinition.Type = p.ParseType()
	if p.peek() == keyword.AT {
		fieldDefinition.Directives = p.parseDirectiveList()
		fieldDefinition.HasDirectives = len(fieldDefinition.Directives.Refs) > 0
	}

	p.document.FieldDefinitions = append(p.document.FieldDefinitions, fieldDefinition)
	return len(p.document.FieldDefinitions) - 1
}

func (p *Parser) parseNamedType() (ref int) {
	ident := p.mustRead(keyword.IDENT)
	namedType := ast.Type{
		TypeKind: ast.TypeKindNamed,
		Name:     ident.Literal,
	}
	p.document.Types = append(p.document.Types, namedType)
	return len(p.document.Types) - 1
}

func (p *Parser) ParseType() (ref int) {

	first := p.peek()

	if first == keyword.IDENT {

		namedType := ast.Type{
			TypeKind: ast.TypeKindNamed,
			Name:     p.read().Literal,
			OfType:   -1,
		}

		p.document.Types = append(p.document.Types, namedType)
		ref = len(p.document.Types) - 1

	} else if first == keyword.LBRACK {

		openList := p.read()
		ofType := p.ParseType()
		closeList := p.mustRead(keyword.RBRACK)

		listType := ast.Type{
			TypeKind: ast.TypeKindList,
			Open:     openList.TextPosition,
			Close:    closeList.TextPosition,
			OfType:   ofType,
		}

		p.document.Types = append(p.document.Types, listType)
		ref = len(p.document.Types) - 1

	} else {
		p.errUnexpectedToken(p.read(), keyword.IDENT, keyword.LBRACK)
		return
	}

	next := p.peek()
	if next == keyword.BANG {
		nonNull := ast.Type{
			TypeKind: ast.TypeKindNonNull,
			Bang:     p.read().TextPosition,
			OfType:   ref,
		}

		if p.peek() == keyword.BANG {
			p.errUnexpectedToken(p.read())
			return
		}

		p.document.Types = append(p.document.Types, nonNull)
		ref = len(p.document.Types) - 1
	}

	return
}

func (p *Parser) parseDescription() ast.Description {
	tok := p.read()
	return ast.Description{
		IsDefined:     true,
		Content:       tok.Literal,
		Position:      tok.TextPosition,
		IsBlockString: tok.Keyword == keyword.BLOCKSTRING,
	}
}

func (p *Parser) parseInputValueDefinitionList(closingKeyword keyword.Keyword) (list ast.InputValueDefinitionList) {

	list.LPAREN = p.read().TextPosition

	for {
		next := p.peek()
		switch next {
		case closingKeyword:
			list.RPAREN = p.read().TextPosition
			return
		case keyword.STRING, keyword.BLOCKSTRING, keyword.IDENT:
			ref := p.parseInputValueDefinition()
			if cap(list.Refs) == 0 {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			list.Refs = append(list.Refs, ref)
		default:
			p.errUnexpectedToken(p.read())
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseInputValueDefinition() int {

	var inputValueDefinition ast.InputValueDefinition

	name := p.peek()
	switch name {
	case keyword.STRING, keyword.BLOCKSTRING:
		inputValueDefinition.Description = p.parseDescription()
	case keyword.IDENT:
		break
	default:
		p.errUnexpectedToken(p.read())
		return -1
	}

	inputValueDefinition.Name = p.read().Literal
	inputValueDefinition.Colon = p.mustRead(keyword.COLON).TextPosition
	inputValueDefinition.Type = p.ParseType()
	if p.peekEquals(keyword.EQUALS) {
		equals := p.read()
		inputValueDefinition.DefaultValue.IsDefined = true
		inputValueDefinition.DefaultValue.Equals = equals.TextPosition
		inputValueDefinition.DefaultValue.Value = p.ParseValue()
	}
	if p.peekEquals(keyword.AT) {
		inputValueDefinition.Directives = p.parseDirectiveList()
		inputValueDefinition.HasDirectives = len(inputValueDefinition.Directives.Refs) > 0
	}

	p.document.InputValueDefinitions = append(p.document.InputValueDefinitions, inputValueDefinition)
	return len(p.document.InputValueDefinitions) - 1
}

func (p *Parser) parseInputObjectTypeDefinition(description *ast.Description) {
	var inputObjectTypeDefinition ast.InputObjectTypeDefinition
	if description != nil {
		inputObjectTypeDefinition.Description = *description
	}
	inputObjectTypeDefinition.InputLiteral = p.mustReadIdentKey(identkeyword.INPUT).TextPosition
	inputObjectTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		inputObjectTypeDefinition.Directives = p.parseDirectiveList()
		inputObjectTypeDefinition.HasDirectives = len(inputObjectTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		inputObjectTypeDefinition.InputFieldsDefinition = p.parseInputValueDefinitionList(keyword.RBRACE)
		inputObjectTypeDefinition.HasInputFieldsDefinition = len(inputObjectTypeDefinition.InputFieldsDefinition.Refs) > 0
	}
	p.document.InputObjectTypeDefinitions = append(p.document.InputObjectTypeDefinitions, inputObjectTypeDefinition)
	ref := len(p.document.InputObjectTypeDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindInputObjectTypeDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(inputObjectTypeDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) parseScalarTypeDefinition(description *ast.Description) {
	var scalarTypeDefinition ast.ScalarTypeDefinition
	if description != nil {
		scalarTypeDefinition.Description = *description
	}
	scalarTypeDefinition.ScalarLiteral = p.mustReadIdentKey(identkeyword.SCALAR).TextPosition
	scalarTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		scalarTypeDefinition.Directives = p.parseDirectiveList()
		scalarTypeDefinition.HasDirectives = len(scalarTypeDefinition.Directives.Refs) > 0
	}
	p.document.ScalarTypeDefinitions = append(p.document.ScalarTypeDefinitions, scalarTypeDefinition)
	ref := len(p.document.ScalarTypeDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindScalarTypeDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(scalarTypeDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) parseInterfaceTypeDefinition(description *ast.Description) {
	var interfaceTypeDefinition ast.InterfaceTypeDefinition
	if description != nil {
		interfaceTypeDefinition.Description = *description
	}
	interfaceTypeDefinition.InterfaceLiteral = p.mustReadIdentKey(identkeyword.INTERFACE).TextPosition
	interfaceTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		interfaceTypeDefinition.Directives = p.parseDirectiveList()
		interfaceTypeDefinition.HasDirectives = len(interfaceTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		interfaceTypeDefinition.FieldsDefinition = p.parseFieldDefinitionList()
		interfaceTypeDefinition.HasFieldDefinitions = len(interfaceTypeDefinition.FieldsDefinition.Refs) > 0
	}
	p.document.InterfaceTypeDefinitions = append(p.document.InterfaceTypeDefinitions, interfaceTypeDefinition)
	ref := len(p.document.InterfaceTypeDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindInterfaceTypeDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(interfaceTypeDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) parseUnionTypeDefinition(description *ast.Description) {
	var unionTypeDefinition ast.UnionTypeDefinition
	if description != nil {
		unionTypeDefinition.Description = *description
	}
	unionTypeDefinition.UnionLiteral = p.mustReadIdentKey(identkeyword.UNION).TextPosition
	unionTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		unionTypeDefinition.Directives = p.parseDirectiveList()
		unionTypeDefinition.HasDirectives = len(unionTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.EQUALS) {
		unionTypeDefinition.Equals = p.mustRead(keyword.EQUALS).TextPosition
		unionTypeDefinition.UnionMemberTypes = p.parseUnionMemberTypes()
		unionTypeDefinition.HasUnionMemberTypes = len(unionTypeDefinition.UnionMemberTypes.Refs) > 0
	}
	p.document.UnionTypeDefinitions = append(p.document.UnionTypeDefinitions, unionTypeDefinition)
	ref := len(p.document.UnionTypeDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindUnionTypeDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(unionTypeDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) parseUnionMemberTypes() (list ast.TypeList) {

	acceptPipe := true
	acceptIdent := true
	expectNext := true

	for {
		next := p.peek()
		switch next {
		case keyword.PIPE:
			if acceptPipe {
				acceptPipe = false
				acceptIdent = true
				expectNext = true
				p.read()
			} else {
				p.errUnexpectedToken(p.read())
				return
			}
		case keyword.IDENT:
			if acceptIdent {
				acceptPipe = true
				acceptIdent = false
				expectNext = false

				ident := p.read()

				namedType := ast.Type{
					TypeKind: ast.TypeKindNamed,
					Name:     ident.Literal,
				}

				p.document.Types = append(p.document.Types, namedType)
				ref := len(p.document.Types) - 1
				if cap(list.Refs) == 0 {
					list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
				}
				list.Refs = append(list.Refs, ref)
			} else {
				return
			}
		default:
			if expectNext {
				p.errUnexpectedToken(p.read())
			}
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseEnumTypeDefinition(description *ast.Description) {
	var enumTypeDefinition ast.EnumTypeDefinition
	if description != nil {
		enumTypeDefinition.Description = *description
	}
	enumTypeDefinition.EnumLiteral = p.mustReadIdentKey(identkeyword.ENUM).TextPosition
	enumTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		enumTypeDefinition.Directives = p.parseDirectiveList()
		enumTypeDefinition.HasDirectives = len(enumTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		enumTypeDefinition.EnumValuesDefinition = p.parseEnumValueDefinitionList()
		enumTypeDefinition.HasEnumValuesDefinition = len(enumTypeDefinition.EnumValuesDefinition.Refs) > 0
	}
	p.document.EnumTypeDefinitions = append(p.document.EnumTypeDefinitions, enumTypeDefinition)
	ref := len(p.document.EnumTypeDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindEnumTypeDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(enumTypeDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) parseEnumValueDefinitionList() (list ast.EnumValueDefinitionList) {

	list.LBRACE = p.mustRead(keyword.LBRACE).TextPosition

	for {
		next := p.peek()
		switch next {
		case keyword.STRING, keyword.BLOCKSTRING, keyword.IDENT:
			ref := p.parseEnumValueDefinition()
			if cap(list.Refs) == 0 {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			list.Refs = append(list.Refs, ref)
		case keyword.RBRACE:
			list.RBRACE = p.read().TextPosition
			return
		default:
			p.errUnexpectedToken(p.read())
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseEnumValueDefinition() int {
	var enumValueDefinition ast.EnumValueDefinition
	next := p.peek()
	switch next {
	case keyword.STRING, keyword.BLOCKSTRING:
		enumValueDefinition.Description = p.parseDescription()
	case keyword.IDENT:
		break
	default:
		p.errUnexpectedToken(p.read())
		return -1
	}

	enumValueDefinition.EnumValue = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		enumValueDefinition.Directives = p.parseDirectiveList()
		enumValueDefinition.HasDirectives = len(enumValueDefinition.Directives.Refs) > 0
	}

	p.document.EnumValueDefinitions = append(p.document.EnumValueDefinitions, enumValueDefinition)
	return len(p.document.EnumValueDefinitions) - 1
}

func (p *Parser) parseDirectiveDefinition(description *ast.Description) {
	var directiveDefinition ast.DirectiveDefinition
	if description != nil {
		directiveDefinition.Description = *description
	}
	directiveDefinition.DirectiveLiteral = p.mustReadIdentKey(identkeyword.DIRECTIVE).TextPosition
	directiveDefinition.At = p.mustRead(keyword.AT).TextPosition
	directiveDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.LPAREN) {
		directiveDefinition.ArgumentsDefinition = p.parseInputValueDefinitionList(keyword.RPAREN)
		directiveDefinition.HasArgumentsDefinitions = len(directiveDefinition.ArgumentsDefinition.Refs) > 0
	}
	directiveDefinition.On = p.mustReadIdentKey(identkeyword.ON).TextPosition
	p.parseDirectiveLocations(&directiveDefinition.DirectiveLocations)
	p.document.DirectiveDefinitions = append(p.document.DirectiveDefinitions, directiveDefinition)
	ref := len(p.document.DirectiveDefinitions) - 1
	node := ast.Node{
		Kind: ast.NodeKindDirectiveDefinition,
		Ref:  ref,
	}
	if p.shouldIndex {
		p.indexNode(directiveDefinition.Name, node)
	}
	p.document.RootNodes = append(p.document.RootNodes, node)
}

func (p *Parser) parseDirectiveLocations(locations *ast.DirectiveLocations) {
	acceptPipe := true
	acceptIdent := true
	expectNext := true
	for {
		next := p.peek()
		switch next {
		case keyword.IDENT:
			if acceptIdent {
				acceptIdent = false
				acceptPipe = true
				expectNext = false

				ident := p.read()
				raw := p.document.Input.ByteSlice(ident.Literal)
				err := locations.SetFromRaw(raw)
				if err != nil {
					p.report.AddExternalError(operationreport.ExternalError{
						Message: fmt.Sprintf("invalid directive location: %s", unsafebytes.BytesToString(raw)),
						Locations: []operationreport.Location{
							{
								Line:   ident.TextPosition.LineStart,
								Column: ident.TextPosition.CharStart,
							},
						},
					})
					if p.reportInternalErrors {
						p.report.AddInternalError(err)
					}
					return
				}

			} else {
				return
			}
		case keyword.PIPE:
			if acceptPipe {
				acceptPipe = false
				acceptIdent = true
				expectNext = true
				p.read()
			} else {
				p.errUnexpectedToken(p.read())
				return
			}
		default:
			if expectNext {
				p.errUnexpectedToken(p.read())
			}
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseSelectionSet() (int, bool) {

	var set ast.SelectionSet

	set.SelectionRefs = p.document.Refs[p.document.NextRefIndex()][:0]
	set.LBrace = p.tokens[p.mustNext(keyword.LBRACE)].TextPosition

	for {
		switch p.peek() {
		case keyword.RBRACE:
			set.RBrace = p.tokens[p.next()].TextPosition

			if len(set.SelectionRefs) == 0 {
				return 0, false
			}

			p.document.SelectionSets = append(p.document.SelectionSets, set)
			return len(p.document.SelectionSets) - 1, true

		case keyword.IDENT, keyword.SPREAD:
			if cap(set.SelectionRefs) == 0 {
				set.SelectionRefs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			ref := p.parseSelection()
			set.SelectionRefs = append(set.SelectionRefs, ref)
		default:
			p.errUnexpectedToken(p.read(), keyword.RBRACE, keyword.IDENT, keyword.SPREAD)
		}

		if p.report.HasErrors() {
			return -1, false
		}
	}
}

func (p *Parser) parseSelection() int {
	next := p.peek()
	switch next {
	case keyword.IDENT:
		p.document.Selections = append(p.document.Selections, ast.Selection{
			Kind: ast.SelectionKindField,
			Ref:  p.parseField(),
		})
		return len(p.document.Selections) - 1
	case keyword.SPREAD:
		return p.parseFragmentSelection(p.tokens[p.next()].TextPosition)
	default:
		p.errUnexpectedToken(p.tokens[p.next()], keyword.IDENT, keyword.SPREAD)
		return -1
	}
}

func (p *Parser) parseFragmentSelection(spread position.Position) int {

	var selection ast.Selection

	next, literal := p.peekLiteral()
	switch next {
	case keyword.LBRACE, keyword.AT:
		selection.Kind = ast.SelectionKindInlineFragment
		selection.Ref = p.parseInlineFragment(spread)
	case keyword.IDENT:
		key := p.identKeywordSliceRef(literal)
		switch key {
		case identkeyword.ON:
			selection.Kind = ast.SelectionKindInlineFragment
			selection.Ref = p.parseInlineFragment(spread)
		default:
			selection.Kind = ast.SelectionKindFragmentSpread
			selection.Ref = p.parseFragmentSpread(spread)
		}
	default:
		p.errUnexpectedToken(p.tokens[p.next()], keyword.IDENT)
	}

	p.document.Selections = append(p.document.Selections, selection)
	return len(p.document.Selections) - 1
}

func (p *Parser) parseField() int {

	var field ast.Field

	firstIdent := p.next()
	if p.tokens[firstIdent].Keyword != keyword.IDENT {
		p.errUnexpectedToken(p.tokens[firstIdent], keyword.IDENT)
	}

	if p.peek() == keyword.COLON {
		field.Alias.IsDefined = true
		field.Alias.Name = p.tokens[firstIdent].Literal
		field.Alias.Colon = p.tokens[p.next()].TextPosition
		field.Name = p.tokens[p.mustNext(keyword.IDENT)].Literal
	} else {
		field.Name = p.tokens[firstIdent].Literal
	}

	if p.peekEquals(keyword.LPAREN) {
		field.Arguments = p.parseArgumentList()
		field.HasArguments = len(field.Arguments.Refs) > 0
	}
	if p.peekEquals(keyword.AT) {
		field.Directives = p.parseDirectiveList()
		field.HasDirectives = len(field.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		field.SelectionSet, field.HasSelections = p.parseSelectionSet()
	}

	p.document.Fields = append(p.document.Fields, field)
	return len(p.document.Fields) - 1
}

func (p *Parser) parseFragmentSpread(spread position.Position) int {
	var fragmentSpread ast.FragmentSpread
	fragmentSpread.Spread = spread
	fragmentSpread.FragmentName = p.mustReadExceptIdentKey(identkeyword.ON).Literal
	if p.peekEquals(keyword.AT) {
		fragmentSpread.Directives = p.parseDirectiveList()
		fragmentSpread.HasDirectives = len(fragmentSpread.Directives.Refs) > 0
	}
	p.document.FragmentSpreads = append(p.document.FragmentSpreads, fragmentSpread)
	return len(p.document.FragmentSpreads) - 1
}

func (p *Parser) parseInlineFragment(spread position.Position) int {
	fragment := ast.InlineFragment{
		TypeCondition: ast.TypeCondition{
			Type: -1,
		},
	}
	fragment.Spread = spread
	if p.peekEqualsIdentKey(identkeyword.ON) {
		fragment.TypeCondition = p.parseTypeCondition()
	}
	if p.peekEquals(keyword.AT) {
		fragment.Directives = p.parseDirectiveList()
		fragment.HasDirectives = len(fragment.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		fragment.SelectionSet, fragment.HasSelections = p.parseSelectionSet()
	}
	p.document.InlineFragments = append(p.document.InlineFragments, fragment)
	return len(p.document.InlineFragments) - 1
}

func (p *Parser) parseTypeCondition() (typeCondition ast.TypeCondition) {
	typeCondition.On = p.mustReadIdentKey(identkeyword.ON).TextPosition
	typeCondition.Type = p.parseNamedType()
	return
}

func (p *Parser) parseOperationDefinition() {

	var operationDefinition ast.OperationDefinition

	next, literal := p.peekLiteral()
	switch next {
	case keyword.IDENT:
		key := p.identKeywordSliceRef(literal)
		switch key {
		case identkeyword.QUERY:
			operationDefinition.OperationTypeLiteral = p.read().TextPosition
			operationDefinition.OperationType = ast.OperationTypeQuery
		case identkeyword.MUTATION:
			operationDefinition.OperationTypeLiteral = p.read().TextPosition
			operationDefinition.OperationType = ast.OperationTypeMutation
		case identkeyword.SUBSCRIPTION:
			operationDefinition.OperationTypeLiteral = p.read().TextPosition
			operationDefinition.OperationType = ast.OperationTypeSubscription
		default:
			p.errUnexpectedIdentKey(p.read(), key, identkeyword.QUERY, identkeyword.MUTATION, identkeyword.SUBSCRIPTION)
			return
		}
	case keyword.LBRACE:
		operationDefinition.OperationType = ast.OperationTypeQuery
		operationDefinition.SelectionSet, operationDefinition.HasSelections = p.parseSelectionSet()
		p.document.OperationDefinitions = append(p.document.OperationDefinitions, operationDefinition)
		ref := len(p.document.OperationDefinitions) - 1
		rootNode := ast.Node{
			Kind: ast.NodeKindOperationDefinition,
			Ref:  ref,
		}
		p.document.RootNodes = append(p.document.RootNodes, rootNode)
		return
	default:
		p.errUnexpectedToken(p.read(), keyword.IDENT, keyword.LBRACE)
		return
	}

	if p.peekEquals(keyword.IDENT) {
		operationDefinition.Name = p.read().Literal
	}
	if p.peekEquals(keyword.LPAREN) {
		operationDefinition.VariableDefinitions = p.parseVariableDefinitionList()
		operationDefinition.HasVariableDefinitions = len(operationDefinition.VariableDefinitions.Refs) > 0
	}
	if p.peekEquals(keyword.AT) {
		operationDefinition.Directives = p.parseDirectiveList()
		operationDefinition.HasDirectives = len(operationDefinition.Directives.Refs) > 0
	}

	operationDefinition.SelectionSet, operationDefinition.HasSelections = p.parseSelectionSet()

	p.document.OperationDefinitions = append(p.document.OperationDefinitions, operationDefinition)
	ref := len(p.document.OperationDefinitions) - 1
	rootNode := ast.Node{
		Kind: ast.NodeKindOperationDefinition,
		Ref:  ref,
	}
	p.document.RootNodes = append(p.document.RootNodes, rootNode)
}

func (p *Parser) parseVariableDefinitionList() (list ast.VariableDefinitionList) {

	list.LPAREN = p.mustRead(keyword.LPAREN).TextPosition

	for {
		next := p.peek()
		switch next {
		case keyword.RPAREN:
			list.RPAREN = p.read().TextPosition
			return
		case keyword.DOLLAR:
			if cap(list.Refs) == 0 {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			ref := p.parseVariableDefinition()
			if cap(list.Refs) == 0 {
				list.Refs = p.document.Refs[p.document.NextRefIndex()][:0]
			}
			list.Refs = append(list.Refs, ref)
		default:
			p.errUnexpectedToken(p.read(), keyword.RPAREN, keyword.DOLLAR)
			return
		}

		if p.report.HasErrors() {
			return
		}
	}
}

func (p *Parser) parseVariableDefinition() int {

	var variableDefinition ast.VariableDefinition

	variableDefinition.VariableValue.Kind = ast.ValueKindVariable
	variableDefinition.VariableValue.Ref = p.parseVariableValue()

	variableDefinition.Colon = p.mustRead(keyword.COLON).TextPosition
	variableDefinition.Type = p.ParseType()
	if p.peekEquals(keyword.EQUALS) {
		variableDefinition.DefaultValue = p.parseDefaultValue()
	}
	if p.peekEquals(keyword.AT) {
		variableDefinition.Directives = p.parseDirectiveList()
		variableDefinition.HasDirectives = len(variableDefinition.Directives.Refs) > 0
	}
	p.document.VariableDefinitions = append(p.document.VariableDefinitions, variableDefinition)
	return len(p.document.VariableDefinitions) - 1
}

func (p *Parser) parseDefaultValue() ast.DefaultValue {
	equals := p.mustRead(keyword.EQUALS).TextPosition
	value := p.ParseValue()
	return ast.DefaultValue{
		IsDefined: true,
		Equals:    equals,
		Value:     value,
	}
}

func (p *Parser) parseFragmentDefinition() {
	var fragmentDefinition ast.FragmentDefinition
	fragmentDefinition.FragmentLiteral = p.mustReadIdentKey(identkeyword.FRAGMENT).TextPosition
	fragmentDefinition.Name = p.mustRead(keyword.IDENT).Literal
	fragmentDefinition.TypeCondition = p.parseTypeCondition()
	if p.peekEquals(keyword.AT) {
		fragmentDefinition.Directives = p.parseDirectiveList()
	}
	fragmentDefinition.SelectionSet, fragmentDefinition.HasSelections = p.parseSelectionSet()
	p.document.FragmentDefinitions = append(p.document.FragmentDefinitions, fragmentDefinition)

	ref := len(p.document.FragmentDefinitions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{
		Kind: ast.NodeKindFragmentDefinition,
		Ref:  ref,
	})
}

func (p *Parser) parseExtension() {
	extend := p.mustReadIdentKey(identkeyword.EXTEND).TextPosition
	next, literal := p.peekLiteral()

	if next != keyword.IDENT {
		p.errUnexpectedToken(p.read(), keyword.IDENT)
		return
	}

	key := p.identKeywordSliceRef(literal)

	switch key {
	case identkeyword.SCHEMA:
		p.parseSchemaExtension(extend)
	case identkeyword.TYPE:
		p.parseObjectTypeExtension(extend)
	case identkeyword.INTERFACE:
		p.parseInterfaceTypeExtension(extend)
	case identkeyword.SCALAR:
		p.parseScalarTypeExtension(extend)
	case identkeyword.UNION:
		p.parseUnionTypeExtension(extend)
	case identkeyword.ENUM:
		p.parseEnumTypeExtension(extend)
	case identkeyword.INPUT:
		p.parseInputObjectTypeExtension(extend)
	default:
		p.errUnexpectedIdentKey(p.read(), key, identkeyword.SCHEMA, identkeyword.TYPE, identkeyword.INTERFACE, identkeyword.SCALAR, identkeyword.UNION, identkeyword.ENUM, identkeyword.INPUT)
	}
}

func (p *Parser) parseSchemaExtension(extend position.Position) {
	schemaLiteral := p.read()
	schemaDefinition := ast.SchemaDefinition{
		SchemaLiteral: schemaLiteral.TextPosition,
	}
	if p.peekEquals(keyword.AT) {
		schemaDefinition.Directives = p.parseDirectiveList()
		schemaDefinition.HasDirectives = len(schemaDefinition.Directives.Refs) > 0
	}
	p.parseRootOperationTypeDefinitionList(&schemaDefinition.RootOperationTypeDefinitions)

	schemaExtension := ast.SchemaExtension{
		ExtendLiteral:    extend,
		SchemaDefinition: schemaDefinition,
	}
	p.document.SchemaExtensions = append(p.document.SchemaExtensions, schemaExtension)
	ref := len(p.document.SchemaExtensions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{Ref: ref, Kind: ast.NodeKindSchemaExtension})
}

func (p *Parser) parseObjectTypeExtension(extend position.Position) {
	var objectTypeDefinition ast.ObjectTypeDefinition
	objectTypeDefinition.TypeLiteral = p.mustReadIdentKey(identkeyword.TYPE).TextPosition
	objectTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEqualsIdentKey(identkeyword.IMPLEMENTS) {
		objectTypeDefinition.ImplementsInterfaces = p.parseImplementsInterfaces()
	}
	if p.peekEquals(keyword.AT) {
		objectTypeDefinition.Directives = p.parseDirectiveList()
		objectTypeDefinition.HasDirectives = len(objectTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		objectTypeDefinition.FieldsDefinition = p.parseFieldDefinitionList()
		objectTypeDefinition.HasFieldDefinitions = len(objectTypeDefinition.FieldsDefinition.Refs) > 0
	}
	objectTypeExtension := ast.ObjectTypeExtension{
		ExtendLiteral:        extend,
		ObjectTypeDefinition: objectTypeDefinition,
	}
	p.document.ObjectTypeExtensions = append(p.document.ObjectTypeExtensions, objectTypeExtension)
	ref := len(p.document.ObjectTypeExtensions) - 1
	node := ast.Node{Ref: ref, Kind: ast.NodeKindObjectTypeExtension}
	p.document.RootNodes = append(p.document.RootNodes, node)

	if p.shouldIndex {
		p.indexNode(objectTypeDefinition.Name, node)
	}
}

func (p *Parser) parseInterfaceTypeExtension(extend position.Position) {
	var interfaceTypeDefinition ast.InterfaceTypeDefinition
	interfaceTypeDefinition.InterfaceLiteral = p.mustReadIdentKey(identkeyword.INTERFACE).TextPosition
	interfaceTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		interfaceTypeDefinition.Directives = p.parseDirectiveList()
		interfaceTypeDefinition.HasDirectives = len(interfaceTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		interfaceTypeDefinition.FieldsDefinition = p.parseFieldDefinitionList()
		interfaceTypeDefinition.HasFieldDefinitions = len(interfaceTypeDefinition.FieldsDefinition.Refs) > 0
	}
	interfaceTypeExtension := ast.InterfaceTypeExtension{
		ExtendLiteral:           extend,
		InterfaceTypeDefinition: interfaceTypeDefinition,
	}
	p.document.InterfaceTypeExtensions = append(p.document.InterfaceTypeExtensions, interfaceTypeExtension)
	ref := len(p.document.InterfaceTypeExtensions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{Ref: ref, Kind: ast.NodeKindInterfaceTypeExtension})
}

func (p *Parser) parseScalarTypeExtension(extend position.Position) {
	var scalarTypeDefinition ast.ScalarTypeDefinition
	scalarTypeDefinition.ScalarLiteral = p.mustReadIdentKey(identkeyword.SCALAR).TextPosition
	scalarTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		scalarTypeDefinition.Directives = p.parseDirectiveList()
		scalarTypeDefinition.HasDirectives = len(scalarTypeDefinition.Directives.Refs) > 0
	}
	scalarTypeExtension := ast.ScalarTypeExtension{
		ExtendLiteral:        extend,
		ScalarTypeDefinition: scalarTypeDefinition,
	}
	p.document.ScalarTypeExtensions = append(p.document.ScalarTypeExtensions, scalarTypeExtension)
	ref := len(p.document.ScalarTypeExtensions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{Ref: ref, Kind: ast.NodeKindScalarTypeExtension})
}

func (p *Parser) parseUnionTypeExtension(extend position.Position) {
	var unionTypeDefinition ast.UnionTypeDefinition
	unionTypeDefinition.UnionLiteral = p.mustReadIdentKey(identkeyword.UNION).TextPosition
	unionTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		unionTypeDefinition.Directives = p.parseDirectiveList()
		unionTypeDefinition.HasDirectives = len(unionTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.EQUALS) {
		unionTypeDefinition.Equals = p.mustRead(keyword.EQUALS).TextPosition
		unionTypeDefinition.UnionMemberTypes = p.parseUnionMemberTypes()
		unionTypeDefinition.HasUnionMemberTypes = len(unionTypeDefinition.UnionMemberTypes.Refs) > 0
	}
	unionTypeExtension := ast.UnionTypeExtension{
		ExtendLiteral:       extend,
		UnionTypeDefinition: unionTypeDefinition,
	}
	p.document.UnionTypeExtensions = append(p.document.UnionTypeExtensions, unionTypeExtension)
	ref := len(p.document.UnionTypeExtensions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{Ref: ref, Kind: ast.NodeKindUnionTypeExtension})
}

func (p *Parser) parseEnumTypeExtension(extend position.Position) {
	var enumTypeDefinition ast.EnumTypeDefinition
	enumTypeDefinition.EnumLiteral = p.mustReadIdentKey(identkeyword.ENUM).TextPosition
	enumTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		enumTypeDefinition.Directives = p.parseDirectiveList()
		enumTypeDefinition.HasDirectives = len(enumTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		enumTypeDefinition.EnumValuesDefinition = p.parseEnumValueDefinitionList()
		enumTypeDefinition.HasEnumValuesDefinition = len(enumTypeDefinition.EnumValuesDefinition.Refs) > 0
	}
	enumTypeExtension := ast.EnumTypeExtension{
		ExtendLiteral:      extend,
		EnumTypeDefinition: enumTypeDefinition,
	}
	p.document.EnumTypeExtensions = append(p.document.EnumTypeExtensions, enumTypeExtension)
	ref := len(p.document.EnumTypeExtensions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{Ref: ref, Kind: ast.NodeKindEnumTypeExtension})
}

func (p *Parser) parseInputObjectTypeExtension(extend position.Position) {
	var inputObjectTypeDefinition ast.InputObjectTypeDefinition
	inputObjectTypeDefinition.InputLiteral = p.mustReadIdentKey(identkeyword.INPUT).TextPosition
	inputObjectTypeDefinition.Name = p.mustRead(keyword.IDENT).Literal
	if p.peekEquals(keyword.AT) {
		inputObjectTypeDefinition.Directives = p.parseDirectiveList()
		inputObjectTypeDefinition.HasDirectives = len(inputObjectTypeDefinition.Directives.Refs) > 0
	}
	if p.peekEquals(keyword.LBRACE) {
		inputObjectTypeDefinition.InputFieldsDefinition = p.parseInputValueDefinitionList(keyword.RBRACE)
		inputObjectTypeDefinition.HasInputFieldsDefinition = len(inputObjectTypeDefinition.InputFieldsDefinition.Refs) > 0
	}
	inputObjectTypeExtension := ast.InputObjectTypeExtension{
		ExtendLiteral:             extend,
		InputObjectTypeDefinition: inputObjectTypeDefinition,
	}
	p.document.InputObjectTypeExtensions = append(p.document.InputObjectTypeExtensions, inputObjectTypeExtension)
	ref := len(p.document.InputObjectTypeExtensions) - 1
	p.document.RootNodes = append(p.document.RootNodes, ast.Node{Ref: ref, Kind: ast.NodeKindInputObjectTypeExtension})
}
