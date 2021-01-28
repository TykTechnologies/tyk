package graphql_datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/tidwall/sjson"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astnormalization"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/astprinter"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/federation"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
	"github.com/jensneuse/graphql-go-tools/pkg/pool"
)

const (
	UniqueIdentifier = "graphql"
)

type Planner struct {
	visitor                    *plan.Visitor
	config                     Configuration
	id                         string
	upstreamOperation          *ast.Document
	upstreamVariables          []byte
	nodes                      []ast.Node
	variables                  resolve.Variables
	lastFieldEnclosingTypeName string
	disallowSingleFlight       bool
	hasFederationRoot          bool
	extractEntities            bool
	client                     httpclient.Client
	isNested bool
}

type Configuration struct {
	Fetch        FetchConfiguration
	Subscription SubscriptionConfiguration
	Federation   FederationConfiguration
}

func ConfigJson(config Configuration) json.RawMessage {
	out, _ := json.Marshal(config)
	return out
}

type FederationConfiguration struct {
	Enabled    bool
	ServiceSDL string
}

type SubscriptionConfiguration struct {
	URL string
}

type FetchConfiguration struct {
	URL    string
	Method string
	Header http.Header
}

func (c *Configuration) ApplyDefaults() {
	if c.Fetch.Method == "" {
		c.Fetch.Method = "POST"
	}
}

func (p *Planner) Register(visitor *plan.Visitor, config json.RawMessage, isNested bool) error {
	p.visitor = visitor
	p.visitor.Walker.RegisterDocumentVisitor(p)
	p.visitor.Walker.RegisterFieldVisitor(p)
	p.visitor.Walker.RegisterOperationDefinitionVisitor(p)
	p.visitor.Walker.RegisterSelectionSetVisitor(p)
	p.visitor.Walker.RegisterEnterArgumentVisitor(p)

	err := json.Unmarshal(config, &p.config)
	if err != nil {
		return err
	}

	p.config.ApplyDefaults()
	p.isNested = isNested

	return nil
}

func (p *Planner) ConfigureFetch() plan.FetchConfiguration {

	var input []byte
	if p.extractEntities {
		input, _ = sjson.SetRawBytes(input, "extract_entities", []byte("true"))
	}
	input = httpclient.SetInputBodyWithPath(input, p.upstreamVariables, "variables")
	input = httpclient.SetInputBodyWithPath(input, p.printOperation(), "query")

	header, err := json.Marshal(p.config.Fetch.Header)
	if err == nil && len(header) != 0 && !bytes.Equal(header, literal.NULL) {
		input = httpclient.SetInputHeader(input, header)
	}

	input = httpclient.SetInputURL(input, []byte(p.config.Fetch.URL))
	input = httpclient.SetInputMethod(input, []byte(p.config.Fetch.Method))

	return plan.FetchConfiguration{
		Input: string(input),
		DataSource: &Source{
			client: p.client,
		},
		Variables:            p.variables,
		DisallowSingleFlight: p.disallowSingleFlight,
	}
}

func (p *Planner) ConfigureSubscription() plan.SubscriptionConfiguration {

	input := httpclient.SetInputBodyWithPath(nil, p.upstreamVariables, "variables")
	input = httpclient.SetInputBodyWithPath(input, p.printOperation(), "query")
	input = httpclient.SetInputURL(input, []byte(p.config.Subscription.URL))

	header, err := json.Marshal(p.config.Fetch.Header)
	if err == nil && len(header) != 0 && !bytes.Equal(header, literal.NULL) {
		input = httpclient.SetInputHeader(input, header)
	}

	return plan.SubscriptionConfiguration{
		Input:                 string(input),
		SubscriptionManagerID: "graphql_websocket_subscription",
	}
}

func (p *Planner) EnterOperationDefinition(ref int) {
	operationType := p.visitor.Operation.OperationDefinitions[ref].OperationType
	if p.isNested {
		operationType = ast.OperationTypeQuery
	}
	definition := p.upstreamOperation.AddOperationDefinitionToRootNodes(ast.OperationDefinition{
		OperationType: operationType,
	})
	p.disallowSingleFlight = operationType == ast.OperationTypeMutation
	p.nodes = append(p.nodes, definition)
}

func (p *Planner) LeaveOperationDefinition(ref int) {
	p.nodes = p.nodes[:len(p.nodes)-1]
}

func (p *Planner) EnterSelectionSet(ref int) {
	parent := p.nodes[len(p.nodes)-1]
	set := p.upstreamOperation.AddSelectionSet()
	switch parent.Kind {
	case ast.NodeKindOperationDefinition:
		p.upstreamOperation.OperationDefinitions[parent.Ref].HasSelections = true
		p.upstreamOperation.OperationDefinitions[parent.Ref].SelectionSet = set.Ref
	case ast.NodeKindField:
		p.upstreamOperation.Fields[parent.Ref].HasSelections = true
		p.upstreamOperation.Fields[parent.Ref].SelectionSet = set.Ref
	case ast.NodeKindInlineFragment:
		p.upstreamOperation.InlineFragments[parent.Ref].HasSelections = true
		p.upstreamOperation.InlineFragments[parent.Ref].SelectionSet = set.Ref
	}
	p.nodes = append(p.nodes, set)
}

func (p *Planner) LeaveSelectionSet(ref int) {
	p.nodes = p.nodes[:len(p.nodes)-1]
}

func (p *Planner) EnterField(ref int) {

	p.lastFieldEnclosingTypeName = p.visitor.Walker.EnclosingTypeDefinition.NameString(p.visitor.Definition)

	p.handleFederation(ref)

	p.addField(ref)

	// fmt.Printf("Planner::%s::%s::EnterField::%s::%d\n", p.id, p.visitor.Walker.Path.DotDelimitedString(), p.visitor.Operation.FieldNameString(ref), ref)

	upstreamFieldRef := p.nodes[len(p.nodes)-1].Ref
	typeName := p.lastFieldEnclosingTypeName
	fieldName := p.visitor.Operation.FieldNameString(ref)
	fieldConfiguration := p.visitor.Config.Fields.ForTypeField(typeName, fieldName)
	if fieldConfiguration == nil {
		return
	}
	for i := range fieldConfiguration.Arguments {
		argumentConfiguration := fieldConfiguration.Arguments[i]
		p.configureArgument(upstreamFieldRef, ref, *fieldConfiguration, argumentConfiguration)
	}
}

func (p *Planner) LeaveField(ref int) {
	// fmt.Printf("Planner::%s::%s::LeaveField::%s::%d\n", p.id, p.visitor.Walker.Path.DotDelimitedString(), p.visitor.Operation.FieldNameString(ref), ref)
	p.nodes = p.nodes[:len(p.nodes)-1]
}

func (p *Planner) EnterArgument(ref int) {

}

func (p *Planner) EnterDocument(operation, definition *ast.Document) {
	if p.upstreamOperation == nil {
		p.upstreamOperation = ast.NewDocument()
	} else {
		p.upstreamOperation.Reset()
	}
	p.nodes = p.nodes[:0]
	p.upstreamVariables = nil
	p.variables = p.variables[:0]
	p.disallowSingleFlight = false
	p.hasFederationRoot = false
	p.extractEntities = false
}

func (p *Planner) LeaveDocument(operation, definition *ast.Document) {

}

func (p *Planner) handleFederation(fieldRef int) {
	if !p.config.Federation.Enabled || // federation must be enabled
		p.hasFederationRoot || // should not already have federation root field
		!p.isNestedRequest() { // must be nested, otherwise it's a regular query
		return
	}
	p.hasFederationRoot = true
	// query($representations: [_Any!]!){_entities(representations: $representations){... on Product
	p.addRepresentationsVariableDefinition() // $representations: [_Any!]!
	p.addEntitiesSelectionSet()              // {_entities(representations: $representations)
	p.addOneTypeInlineFragment()             // ... on Product
	p.addRepresentationsVariable()           // "variables\":{\"representations\":[{\"upc\":\"$$0$$\",\"__typename\":\"Product\"}]}}
}

func (p *Planner) addRepresentationsVariable() {
	// "variables\":{\"representations\":[{\"upc\":\"$$0$$\",\"__typename\":\"Product\"}]}}
	parser := astparser.NewParser()
	doc := ast.NewDocument()
	doc.Input.ResetInputString(p.config.Federation.ServiceSDL)
	report := &operationreport.Report{}
	parser.Parse(doc, report)
	if report.HasErrors() {
		p.visitor.Walker.StopWithInternalErr(fmt.Errorf("GraphQL Planner: failed parsing Federation SDL"))
		return
	}
	directive := -1
	for i := range doc.ObjectTypeExtensions {
		if p.lastFieldEnclosingTypeName == doc.ObjectTypeExtensionNameString(i) {
			for _, j := range doc.ObjectTypeExtensions[i].Directives.Refs {
				if doc.DirectiveNameString(j) == "key" {
					directive = j
					break
				}
			}
			break
		}
	}
	for i := range doc.ObjectTypeDefinitions {
		if p.lastFieldEnclosingTypeName == doc.ObjectTypeDefinitionNameString(i) {
			for _, j := range doc.ObjectTypeDefinitions[i].Directives.Refs {
				if doc.DirectiveNameString(j) == "key" {
					directive = j
					break
				}
			}
			break
		}
	}
	if directive == -1 {
		return
	}
	value, exists := doc.DirectiveArgumentValueByName(directive, []byte("fields"))
	if !exists {
		return
	}
	if value.Kind != ast.ValueKindString {
		return
	}
	fieldsStr := doc.StringValueContentString(value.Ref)
	fields := strings.Split(fieldsStr, " ")
	representationsJson, _ := sjson.SetRawBytes(nil, "__typename", []byte("\""+p.lastFieldEnclosingTypeName+"\""))
	for i := range fields {
		variable, exists := p.variables.AddVariable(&resolve.ObjectVariable{
			Path: []string{fields[i]},
		}, true)
		if exists {
			continue
		}
		representationsJson, _ = sjson.SetRawBytes(representationsJson, fields[i], []byte(variable))
	}
	representationsJson = append([]byte("["), append(representationsJson, []byte("]")...)...)
	p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, "representations", representationsJson)
	p.extractEntities = true
}

func (p *Planner) addOneTypeInlineFragment() {
	selectionSet := p.upstreamOperation.AddSelectionSet()
	typeRef := p.upstreamOperation.AddNamedType([]byte(p.lastFieldEnclosingTypeName))
	inlineFragment := p.upstreamOperation.AddInlineFragment(ast.InlineFragment{
		HasSelections: true,
		SelectionSet:  selectionSet.Ref,
		TypeCondition: ast.TypeCondition{
			Type: typeRef,
		},
	})
	p.upstreamOperation.AddSelection(p.nodes[len(p.nodes)-1].Ref, ast.Selection{
		Kind: ast.SelectionKindInlineFragment,
		Ref:  inlineFragment,
	})
	p.nodes = append(p.nodes, selectionSet)
}

func (p *Planner) addEntitiesSelectionSet() {

	// $representations
	representationsLiteral := p.upstreamOperation.Input.AppendInputString("representations")
	representationsVariable := p.upstreamOperation.AddVariableValue(ast.VariableValue{
		Name: representationsLiteral,
	})
	representationsArgument := p.upstreamOperation.AddArgument(ast.Argument{
		Name: representationsLiteral,
		Value: ast.Value{
			Kind: ast.ValueKindVariable,
			Ref:  representationsVariable,
		},
	})

	// _entities
	entitiesSelectionSet := p.upstreamOperation.AddSelectionSet()
	entitiesField := p.upstreamOperation.AddField(ast.Field{
		Name:          p.upstreamOperation.Input.AppendInputString("_entities"),
		HasSelections: true,
		HasArguments:  true,
		Arguments: ast.ArgumentList{
			Refs: []int{representationsArgument},
		},
		SelectionSet: entitiesSelectionSet.Ref,
	})
	p.upstreamOperation.AddSelection(p.nodes[len(p.nodes)-1].Ref, ast.Selection{
		Kind: ast.SelectionKindField,
		Ref:  entitiesField.Ref,
	})
	p.nodes = append(p.nodes, entitiesField, entitiesSelectionSet)
}

func (p *Planner) addRepresentationsVariableDefinition() {
	anyType := p.upstreamOperation.AddNamedType([]byte("_Any"))
	nonNullAnyType := p.upstreamOperation.AddType(ast.Type{
		TypeKind: ast.TypeKindNonNull,
		OfType:   anyType,
	})
	listOfNonNullAnyType := p.upstreamOperation.AddType(ast.Type{
		TypeKind: ast.TypeKindList,
		OfType:   nonNullAnyType,
	})
	nonNullListOfNonNullAnyType := p.upstreamOperation.AddType(ast.Type{
		TypeKind: ast.TypeKindNonNull,
		OfType:   listOfNonNullAnyType,
	})
	representationsVariable := p.upstreamOperation.AddVariableValue(ast.VariableValue{
		Name: p.upstreamOperation.Input.AppendInputBytes([]byte("representations")),
	})
	p.upstreamOperation.AddVariableDefinitionToOperationDefinition(p.nodes[0].Ref, representationsVariable, nonNullListOfNonNullAnyType)
}

func (p *Planner) isNestedRequest() bool {
	for i := range p.nodes {
		if p.nodes[i].Kind == ast.NodeKindField {
			return false
		}
	}
	selectionSetAncestors := 0
	for i := range p.visitor.Walker.Ancestors {
		if p.visitor.Walker.Ancestors[i].Kind == ast.NodeKindSelectionSet {
			selectionSetAncestors++
			if selectionSetAncestors == 2 {
				return true
			}
		}
	}
	return false
}

func (p *Planner) configureArgument(upstreamFieldRef, downstreamFieldRef int, fieldConfig plan.FieldConfiguration, argumentConfiguration plan.ArgumentConfiguration) {
	switch argumentConfiguration.SourceType {
	case plan.FieldArgumentSource:
		p.configureFieldArgumentSource(upstreamFieldRef, downstreamFieldRef, argumentConfiguration.Name, argumentConfiguration.SourcePath)
	case plan.ObjectFieldSource:
		p.configureObjectFieldSource(upstreamFieldRef, downstreamFieldRef, fieldConfig, argumentConfiguration)
	}
}

func (p *Planner) configureFieldArgumentSource(upstreamFieldRef, downstreamFieldRef int, argumentName string, sourcePath []string) {
	fieldArgument, ok := p.visitor.Operation.FieldArgument(downstreamFieldRef, []byte(argumentName))
	if !ok {
		return
	}
	value := p.visitor.Operation.ArgumentValue(fieldArgument)
	if value.Kind != ast.ValueKindVariable {
		p.applyInlineFieldArgument(upstreamFieldRef, downstreamFieldRef, argumentName, sourcePath)
		return
	}
	variableName := p.visitor.Operation.VariableValueNameBytes(value.Ref)
	variableNameStr := p.visitor.Operation.VariableValueNameString(value.Ref)

	variableDefinition, ok := p.visitor.Operation.VariableDefinitionByNameAndOperation(p.visitor.Walker.Ancestors[0].Ref, variableName)
	if !ok {
		return
	}

	variableDefinitionType := p.visitor.Operation.VariableDefinitions[variableDefinition].Type
	wrapValueInQuotes := p.visitor.Operation.TypeValueNeedsQuotes(variableDefinitionType, p.visitor.Definition)

	contextVariableName, exists := p.variables.AddVariable(&resolve.ContextVariable{Path: []string{variableNameStr}}, wrapValueInQuotes)
	variableValueRef, argRef := p.upstreamOperation.AddVariableValueArgument([]byte(argumentName), variableName) // add the argument to the field, but don't redefine it
	p.upstreamOperation.AddArgumentToField(upstreamFieldRef, argRef)

	if exists { // if the variable exists we don't have to put it onto the variables declaration again, skip
		return
	}

	for _, i := range p.visitor.Operation.OperationDefinitions[p.visitor.Walker.Ancestors[0].Ref].VariableDefinitions.Refs {
		ref := p.visitor.Operation.VariableDefinitions[i].VariableValue.Ref
		if !p.visitor.Operation.VariableValueNameBytes(ref).Equals(variableName) {
			continue
		}
		importedType := p.visitor.Importer.ImportType(p.visitor.Operation.VariableDefinitions[i].Type, p.visitor.Operation, p.upstreamOperation)
		p.upstreamOperation.AddVariableDefinitionToOperationDefinition(p.nodes[0].Ref, variableValueRef, importedType)
	}

	p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, variableNameStr, []byte(contextVariableName))
}

func (p *Planner) applyInlineFieldArgument(upstreamField, downstreamField int, argumentName string, sourcePath []string) {
	fieldArgument, ok := p.visitor.Operation.FieldArgument(downstreamField, []byte(argumentName))
	if !ok {
		return
	}
	value := p.visitor.Operation.ArgumentValue(fieldArgument)
	importedValue := p.visitor.Importer.ImportValue(value, p.visitor.Operation, p.upstreamOperation)
	argRef := p.upstreamOperation.AddArgument(ast.Argument{
		Name:  p.upstreamOperation.Input.AppendInputString(argumentName),
		Value: importedValue,
	})
	p.upstreamOperation.AddArgumentToField(upstreamField, argRef)
	p.addVariableDefinitionsRecursively(value, argumentName, sourcePath)
}

func (p *Planner) addVariableDefinitionsRecursively(value ast.Value, argumentName string, sourcePath []string) {
	switch value.Kind {
	case ast.ValueKindObject:
		for _, i := range p.visitor.Operation.ObjectValues[value.Ref].Refs {
			p.addVariableDefinitionsRecursively(p.visitor.Operation.ObjectFields[i].Value, argumentName, sourcePath)
		}
		return
	case ast.ValueKindList:
		for _, i := range p.visitor.Operation.ListValues[value.Ref].Refs {
			p.addVariableDefinitionsRecursively(p.visitor.Operation.Values[i], argumentName, sourcePath)
		}
		return
	case ast.ValueKindVariable:
		// continue after switch
	default:
		return
	}

	variableName := p.visitor.Operation.VariableValueNameBytes(value.Ref)
	variableNameStr := p.visitor.Operation.VariableValueNameString(value.Ref)
	variableDefinition, exists := p.visitor.Operation.VariableDefinitionByNameAndOperation(p.visitor.Walker.Ancestors[0].Ref, variableName)
	if !exists {
		return
	}
	importedVariableDefinition := p.visitor.Importer.ImportVariableDefinition(variableDefinition, p.visitor.Operation, p.upstreamOperation)
	p.upstreamOperation.AddImportedVariableDefinitionToOperationDefinition(p.nodes[0].Ref, importedVariableDefinition)

	variableDefinitionType := p.visitor.Operation.VariableDefinitions[variableDefinition].Type
	wrapValueInQuotes := p.visitor.Operation.TypeValueNeedsQuotes(variableDefinitionType, p.visitor.Definition)

	contextVariableName, variableExists := p.variables.AddVariable(&resolve.ContextVariable{Path: append(sourcePath, variableNameStr)}, wrapValueInQuotes)
	if variableExists {
		return
	}
	p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, variableNameStr, []byte(contextVariableName))
}

func (p *Planner) configureObjectFieldSource(upstreamFieldRef, downstreamFieldRef int, fieldConfiguration plan.FieldConfiguration, argumentConfiguration plan.ArgumentConfiguration) {
	if len(argumentConfiguration.SourcePath) < 1 {
		return
	}

	fieldName := p.visitor.Operation.FieldNameString(downstreamFieldRef)

	if len(fieldConfiguration.Path) == 1 {
		fieldName = fieldConfiguration.Path[0]
	}

	queryTypeDefinition, exists := p.visitor.Definition.Index.FirstNodeByNameBytes(p.visitor.Definition.Index.QueryTypeName)
	if !exists {
		return
	}
	argumentDefinition := p.visitor.Definition.NodeFieldDefinitionArgumentDefinitionByName(queryTypeDefinition, []byte(fieldName), []byte(argumentConfiguration.Name))
	if argumentDefinition == -1 {
		return
	}

	argumentType := p.visitor.Definition.InputValueDefinitionType(argumentDefinition)
	variableName := p.upstreamOperation.GenerateUnusedVariableDefinitionName(p.nodes[0].Ref)
	variableValue, argument := p.upstreamOperation.AddVariableValueArgument([]byte(argumentConfiguration.Name), variableName)
	p.upstreamOperation.AddArgumentToField(upstreamFieldRef, argument)
	importedType := p.visitor.Importer.ImportType(argumentType, p.visitor.Definition, p.upstreamOperation)
	p.upstreamOperation.AddVariableDefinitionToOperationDefinition(p.nodes[0].Ref, variableValue, importedType)
	wrapVariableInQuotes := p.visitor.Definition.TypeValueNeedsQuotes(argumentType, p.visitor.Definition)

	objectVariableName, exists := p.variables.AddVariable(&resolve.ObjectVariable{Path: argumentConfiguration.SourcePath}, wrapVariableInQuotes)
	if !exists {
		p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, string(variableName), []byte(objectVariableName))
	}
}

func (p *Planner) printOperation() []byte {

	buf := &bytes.Buffer{}

	err := astprinter.Print(p.upstreamOperation, nil, buf)
	if err != nil {
		return nil
	}

	rawQuery := buf.Bytes()

	baseSchema, err := astprinter.PrintString(p.visitor.Definition, nil)
	if err != nil {
		return nil
	}

	federationSchema, err := federation.BuildFederationSchema(baseSchema, p.config.Federation.ServiceSDL)
	if err != nil {
		p.visitor.Walker.StopWithInternalErr(err)
		return nil
	}

	operation := ast.NewDocument()
	definition := ast.NewDocument()
	report := &operationreport.Report{}
	parser := astparser.NewParser()

	definition.Input.ResetInputString(federationSchema)
	operation.Input.ResetInputBytes(rawQuery)

	parser.Parse(operation, report)
	if report.HasErrors() {
		p.visitor.Walker.StopWithInternalErr(fmt.Errorf("printOperation: parse operation failed"))
		return nil
	}

	parser.Parse(definition, report)
	if report.HasErrors() {
		p.visitor.Walker.StopWithInternalErr(fmt.Errorf("printOperation: parse definition failed"))
		return nil
	}

	operationStr, _ := astprinter.PrintStringIndent(operation, definition, "  ")
	schemaStr, _ := astprinter.PrintStringIndent(definition, nil, "  ")
	_, _ = schemaStr, operationStr

	normalizer := astnormalization.NewNormalizer(true, true)
	normalizer.NormalizeOperation(operation, definition, report)

	if report.HasErrors() {
		p.visitor.Walker.StopWithInternalErr(fmt.Errorf("normalization failed"))
		return nil
	}

	buf.Reset()

	err = astprinter.Print(operation, p.visitor.Definition, buf)
	if err != nil {
		p.visitor.Walker.StopWithInternalErr(fmt.Errorf("normalization failed"))
		return nil
	}
	return buf.Bytes()
}

func (p *Planner) addField(ref int) {

	fieldName := p.visitor.Operation.FieldNameString(ref)

	alias := ast.Alias{
		IsDefined: p.visitor.Operation.FieldAliasIsDefined(ref),
	}

	if alias.IsDefined {
		aliasBytes := p.visitor.Operation.FieldAliasBytes(ref)
		alias.Name = p.upstreamOperation.Input.AppendInputBytes(aliasBytes)
	}

	typeName := p.visitor.Walker.EnclosingTypeDefinition.NameString(p.visitor.Definition)
	for i := range p.visitor.Config.Fields {
		if p.visitor.Config.Fields[i].TypeName == typeName &&
			p.visitor.Config.Fields[i].FieldName == fieldName &&
			len(p.visitor.Config.Fields[i].Path) == 1 {
			fieldName = p.visitor.Config.Fields[i].Path[0]
			break
		}
	}

	field := p.upstreamOperation.AddField(ast.Field{
		Name:  p.upstreamOperation.Input.AppendInputString(fieldName),
		Alias: alias,
	})

	selection := ast.Selection{
		Kind: ast.SelectionKindField,
		Ref:  field.Ref,
	}

	p.upstreamOperation.AddSelection(p.nodes[len(p.nodes)-1].Ref, selection)
	p.nodes = append(p.nodes, field)
}

type Factory struct {
	id     int
	Client httpclient.Client
}

func (f *Factory) Planner() plan.DataSourcePlanner {
	f.id++
	return &Planner{
		id:     strconv.Itoa(f.id),
		client: f.Client,
	}
}

var (
	responsePaths = [][]string{
		{"errors"},
		{"data"},
	}
	entitiesPath     = []string{"_entities", "[0]"}
	uniqueIdentifier = []byte(UniqueIdentifier)
)

type Source struct {
	client httpclient.Client
}

func (s *Source) Load(ctx context.Context, input []byte, bufPair *resolve.BufPair) (err error) {
	buf := pool.BytesBuffer.Get()
	defer pool.BytesBuffer.Put(buf)

	err = s.client.Do(ctx, input, buf)
	if err != nil {
		return
	}

	responseData := buf.Bytes()

	extractEntitiesRaw, _, _, _ := jsonparser.Get(input, "extract_entities")
	extractEntities := bytes.Equal(extractEntitiesRaw, literal.TRUE)

	jsonparser.EachKey(responseData, func(i int, bytes []byte, valueType jsonparser.ValueType, err error) {
		switch i {
		case 0:
			bufPair.Errors.WriteBytes(bytes)
		case 1:
			if extractEntities {
				data, _, _, _ := jsonparser.Get(bytes, entitiesPath...)
				bufPair.Data.WriteBytes(data)
				return
			}
			bufPair.Data.WriteBytes(bytes)
		}
	}, responsePaths...)

	return
}

func (s *Source) UniqueIdentifier() []byte {
	return uniqueIdentifier
}
