package graphql_datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/asttransform"
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
)

type Planner struct {
	visitor                            *plan.Visitor
	dataSourceConfig                   plan.DataSourceConfiguration
	config                             Configuration
	upstreamOperation                  *ast.Document
	upstreamVariables                  []byte
	representationsJson                []byte
	nodes                              []ast.Node
	variables                          resolve.Variables
	lastFieldEnclosingTypeName         string
	disallowSingleFlight               bool
	hasFederationRoot                  bool
	extractEntities                    bool
	fetchClient                        *http.Client
	subscriptionClient                 GraphQLSubscriptionClient
	isNested                           bool   // isNested - flags that datasource is nested e.g. field with datasource is not on a query type
	rootTypeName                       string // rootTypeName - holds name of top level type
	rootFieldName                      string // rootFieldName - holds name of root type field
	rootFieldRef                       int    // rootFieldRef - holds ref of root type field
	argTypeRef                         int    // argTypeRef - holds current argument type ref from the definition
	batchFactory                       resolve.DataSourceBatchFactory
	upstreamDefinition                 *ast.Document
	currentVariableDefinition          int
	addDirectivesToVariableDefinitions map[int][]int
}

func (p *Planner) EnterVariableDefinition(ref int) {
	p.currentVariableDefinition = ref
}

func (p *Planner) LeaveVariableDefinition(_ int) {
	p.currentVariableDefinition = -1
}

func (p *Planner) EnterDirective(ref int) {
	parent := p.nodes[len(p.nodes)-1]
	if parent.Kind == ast.NodeKindOperationDefinition && p.currentVariableDefinition != -1 {
		name := p.visitor.Operation.VariableDefinitionNameString(p.currentVariableDefinition)
		_ = name
		p.addDirectivesToVariableDefinitions[p.currentVariableDefinition] = append(p.addDirectivesToVariableDefinitions[p.currentVariableDefinition], ref)
		return
	}
	p.addDirectiveToNode(ref, parent)
}

func (p *Planner) addDirectiveToNode(directiveRef int, node ast.Node) {
	directiveName := p.visitor.Operation.DirectiveNameString(directiveRef)
	operationType := ast.OperationTypeQuery
	if !p.isNested {
		operationType = p.visitor.Operation.OperationDefinitions[p.visitor.Walker.Ancestors[0].Ref].OperationType
	}
	if !p.visitor.Definition.DirectiveIsAllowedOnNodeKind(directiveName, node.Kind, operationType) {
		return
	}
	upstreamDirectiveName := p.dataSourceConfig.Directives.RenameTypeNameOnMatchStr(directiveName)
	if p.upstreamDefinition != nil && !p.upstreamDefinition.DirectiveIsAllowedOnNodeKind(upstreamDirectiveName, node.Kind, operationType) {
		return
	}
	upstreamDirective := p.visitor.Importer.ImportDirectiveWithRename(directiveRef, upstreamDirectiveName, p.visitor.Operation, p.upstreamOperation)
	p.upstreamOperation.AddDirectiveToNode(upstreamDirective, node)

	// The directive is allowed on the node, so we know it exists.
	directive := p.visitor.Operation.Directives[directiveRef]

	var variables []ast.Value

	// Collect all the variable arguments.
	if directive.HasArguments {
		for _, argument := range directive.Arguments.Refs {
			value := p.visitor.Operation.ArgumentValue(argument)
			// TODO: also handle literal values that CONTAIN variables
			if value.Kind == ast.ValueKindVariable {
				variables = append(variables, value)
			}
		}
	}

	// Process each variable, adding it to the upstream operation and
	// variables, if it hasn't already been added. Note: instead of looking
	// up the type of the corresponding argument on the directive definition,
	// this code assumes the type of the variable as defined in the operation
	// is correct and uses the same (possibly mapped) type for the upstream
	// operation.
	for _, value := range variables {
		variableName := p.visitor.Operation.VariableValueNameBytes(value.Ref)

		for _, i := range p.visitor.Operation.OperationDefinitions[p.visitor.Walker.Ancestors[0].Ref].VariableDefinitions.Refs {
			// Find the variable declaration in the downstream operation.
			ref := p.visitor.Operation.VariableDefinitions[i].VariableValue.Ref
			if !p.visitor.Operation.VariableValueNameBytes(ref).Equals(variableName) {
				continue
			}

			// Look up the variable type.
			variableType := p.visitor.Operation.VariableDefinitions[i].Type
			typeName := p.visitor.Operation.ResolveTypeNameString(variableType)

			renderer, err := resolve.NewJSONVariableRendererWithValidationFromTypeRef(p.visitor.Operation, p.visitor.Definition, variableType)
			if err != nil {
				continue
			}

			contextVariable := &resolve.ContextVariable{
				Path:     []string{string(variableName)},
				Renderer: renderer,
			}

			// Try to add the variable to the set of upstream variables.
			contextVariableName, exists := p.variables.AddVariable(contextVariable)

			// If the variable already exists, it also already exists in the
			// upstream operation; there's nothing to add!
			if exists {
				continue
			}

			// Add the variable to the upstream operation. Be sure to map the
			// downstream type to the upstream type, if needed.
			upstreamVariable := p.upstreamOperation.ImportVariableValue(variableName)
			upstreamTypeName := p.visitor.Config.Types.RenameTypeNameOnMatchStr(typeName)
			importedType := p.visitor.Importer.ImportTypeWithRename(p.visitor.Operation.VariableDefinitions[i].Type, p.visitor.Operation, p.upstreamOperation, upstreamTypeName)
			p.upstreamOperation.AddVariableDefinitionToOperationDefinition(p.nodes[0].Ref, upstreamVariable, importedType)

			// Also copy any variable directives in the downstream operation to
			// the upstream operation.
			if add, ok := p.addDirectivesToVariableDefinitions[i]; ok {
				for _, directive := range add {
					p.addDirectiveToNode(directive, ast.Node{Kind: ast.NodeKindVariableDefinition, Ref: i})
				}
			}

			// And finally add the variable to the upstream variables JSON.
			p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, string(variableName), []byte(contextVariableName))
		}
	}
}

func (p *Planner) DownstreamResponseFieldAlias(downstreamFieldRef int) (alias string, exists bool) {
	// If there's no alias but the downstream Query re-uses the same path on different root fields,
	// we rewrite the downstream Query using an alias so that we can have an aliased Query to the upstream
	// while keeping a non aliased Query to the downstream but with a path rewrite on an existing root field.

	fieldName := p.visitor.Operation.FieldNameUnsafeString(downstreamFieldRef)

	if p.visitor.Operation.FieldAliasIsDefined(downstreamFieldRef) {
		return "", false
	}

	typeName := p.visitor.Walker.EnclosingTypeDefinition.NameString(p.visitor.Definition)
	for i := range p.visitor.Config.Fields {
		if p.visitor.Config.Fields[i].TypeName == typeName &&
			p.visitor.Config.Fields[i].FieldName == fieldName &&
			len(p.visitor.Config.Fields[i].Path) == 1 {

			if p.visitor.Config.Fields[i].Path[0] != fieldName {
				aliasBytes := p.visitor.Operation.FieldNameBytes(downstreamFieldRef)
				return string(aliasBytes), true
			}
			break
		}
	}
	return "", false
}

func (p *Planner) DataSourcePlanningBehavior() plan.DataSourcePlanningBehavior {
	return plan.DataSourcePlanningBehavior{
		MergeAliasedRootNodes:      true,
		OverrideFieldPathFromAlias: true,
	}
}

type Configuration struct {
	Fetch          FetchConfiguration
	Subscription   SubscriptionConfiguration
	Federation     FederationConfiguration
	UpstreamSchema string
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

func (p *Planner) Register(visitor *plan.Visitor, configuration plan.DataSourceConfiguration, isNested bool) error {
	p.visitor = visitor
	p.visitor.Walker.RegisterDocumentVisitor(p)
	p.visitor.Walker.RegisterFieldVisitor(p)
	p.visitor.Walker.RegisterOperationDefinitionVisitor(p)
	p.visitor.Walker.RegisterSelectionSetVisitor(p)
	p.visitor.Walker.RegisterEnterArgumentVisitor(p)
	p.visitor.Walker.RegisterInlineFragmentVisitor(p)
	p.visitor.Walker.RegisterEnterDirectiveVisitor(p)
	p.visitor.Walker.RegisterVariableDefinitionVisitor(p)

	p.dataSourceConfig = configuration
	err := json.Unmarshal(configuration.Custom, &p.config)
	if err != nil {
		return err
	}

	p.config.ApplyDefaults()
	p.isNested = isNested

	return nil
}

func (p *Planner) ConfigureFetch() plan.FetchConfiguration {
	var input []byte
	input = httpclient.SetInputBodyWithPath(input, p.upstreamVariables, "variables")
	input = httpclient.SetInputBodyWithPath(input, p.printOperation(), "query")

	header, err := json.Marshal(p.config.Fetch.Header)
	if err == nil && len(header) != 0 && !bytes.Equal(header, literal.NULL) {
		input = httpclient.SetInputHeader(input, header)
	}

	input = httpclient.SetInputURL(input, []byte(p.config.Fetch.URL))
	input = httpclient.SetInputMethod(input, []byte(p.config.Fetch.Method))

	var batchConfig plan.BatchConfig
	// Allow batch query for fetching entities.
	if p.extractEntities && p.batchFactory != nil {
		batchConfig = plan.BatchConfig{
			AllowBatch:   p.extractEntities, // Allow batch query for fetching entities.
			BatchFactory: p.batchFactory,
		}
	}

	return plan.FetchConfiguration{
		Input: string(input),
		DataSource: &Source{
			httpClient: p.fetchClient,
		},
		Variables:            p.variables,
		DisallowSingleFlight: p.disallowSingleFlight,
		ProcessResponseConfig: resolve.ProcessResponseConfig{
			ExtractGraphqlResponse:    true,
			ExtractFederationEntities: p.extractEntities,
		},
		BatchConfig:      batchConfig,
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
		Input: string(input),
		DataSource: &SubscriptionSource{
			client: p.subscriptionClient,
		},
		Variables: p.variables,
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
	for _, selectionRef := range p.visitor.Operation.SelectionSets[ref].SelectionRefs {
		if p.visitor.Operation.Selections[selectionRef].Kind == ast.SelectionKindField {
			if p.visitor.Operation.FieldNameUnsafeString(p.visitor.Operation.Selections[selectionRef].Ref) == "__typename" {
				field := p.upstreamOperation.AddField(ast.Field{
					Name: p.upstreamOperation.Input.AppendInputString("__typename"),
				})
				p.upstreamOperation.AddSelection(set.Ref, ast.Selection{
					Ref:  field.Ref,
					Kind: ast.SelectionKindField,
				})
			}
		}
	}
}

func (p *Planner) LeaveSelectionSet(ref int) {
	p.nodes = p.nodes[:len(p.nodes)-1]
}

func (p *Planner) EnterInlineFragment(ref int) {
	typeCondition := p.visitor.Operation.InlineFragmentTypeConditionName(ref)
	if typeCondition == nil {
		return
	}

	inlineFragment := p.upstreamOperation.AddInlineFragment(ast.InlineFragment{
		TypeCondition: ast.TypeCondition{
			Type: p.upstreamOperation.AddNamedType(p.visitor.Config.Types.RenameTypeNameOnMatchBytes(typeCondition)),
		},
	})

	selection := ast.Selection{
		Kind: ast.SelectionKindInlineFragment,
		Ref:  inlineFragment,
	}

	// add __typename field to selection set which contains typeCondition
	// so that the resolver can distinguish between the response types
	typeNameField := p.upstreamOperation.AddField(ast.Field{
		Name: p.upstreamOperation.Input.AppendInputBytes([]byte("__typename")),
	})
	p.upstreamOperation.AddSelection(p.nodes[len(p.nodes)-1].Ref, ast.Selection{
		Kind: ast.SelectionKindField,
		Ref:  typeNameField.Ref,
	})

	p.upstreamOperation.AddSelection(p.nodes[len(p.nodes)-1].Ref, selection)
	p.nodes = append(p.nodes, ast.Node{Kind: ast.NodeKindInlineFragment, Ref: inlineFragment})
}

func (p *Planner) LeaveInlineFragment(ref int) {
	if p.nodes[len(p.nodes)-1].Kind != ast.NodeKindInlineFragment {
		return
	}
	p.nodes = p.nodes[:len(p.nodes)-1]
}

func (p *Planner) EnterField(ref int) {
	fieldName := p.visitor.Operation.FieldNameString(ref)

	// store root field name and ref
	if p.rootFieldName == "" {
		p.rootFieldName = fieldName
		p.rootFieldRef = ref
	}
	// store root type name
	if p.rootTypeName == "" {
		p.rootTypeName = p.visitor.Walker.EnclosingTypeDefinition.NameString(p.visitor.Definition)
	}

	p.lastFieldEnclosingTypeName = p.visitor.Walker.EnclosingTypeDefinition.NameString(p.visitor.Definition)

	typeName := p.lastFieldEnclosingTypeName

	fieldConfiguration := p.visitor.Config.Fields.ForTypeField(typeName, fieldName)
	if fieldConfiguration == nil {
		p.addField(ref)
		return
	}

	// Note: federated fields always have a field configuration because at
	// least the federation key for the type the field lives on is required
	// (and required fields are specified in the configuration).
	p.handleFederation(fieldConfiguration)
	p.addField(ref)

	upstreamFieldRef := p.nodes[len(p.nodes)-1].Ref

	for i := range fieldConfiguration.Arguments {
		argumentConfiguration := fieldConfiguration.Arguments[i]
		p.configureArgument(upstreamFieldRef, ref, *fieldConfiguration, argumentConfiguration)
	}
}

func (p *Planner) LeaveField(ref int) {
	// fmt.Printf("Planner::%s::%s::LeaveField::%s::%d\n", p.id, p.visitor.Walker.Path.DotDelimitedString(), p.visitor.Operation.FieldNameUnsafeString(ref), ref)
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
	p.representationsJson = p.representationsJson[:0]
	p.disallowSingleFlight = false
	p.hasFederationRoot = false
	p.extractEntities = false

	// reset information about root type
	p.rootTypeName = ""
	p.rootFieldName = ""
	p.rootFieldRef = -1

	// reset info about arg type
	p.argTypeRef = -1

	p.addDirectivesToVariableDefinitions = map[int][]int{}

	p.upstreamDefinition = nil
	if p.config.UpstreamSchema != "" {
		p.upstreamDefinition = ast.NewDocument()
		p.upstreamDefinition.Input.ResetInputString(p.config.UpstreamSchema)
		parser := astparser.NewParser()
		var report operationreport.Report
		parser.Parse(p.upstreamDefinition, &report)
		if report.HasErrors() {
			p.visitor.Walker.StopWithInternalErr(report)
			return
		}
		err := asttransform.MergeDefinitionWithBaseSchema(p.upstreamDefinition)
		if err != nil {
			p.visitor.Walker.StopWithInternalErr(err)
			return
		}
	}
}

func (p *Planner) LeaveDocument(operation, definition *ast.Document) {
}

func (p *Planner) handleFederation(fieldConfig *plan.FieldConfiguration) {
	if !p.config.Federation.Enabled { // federation must be enabled
		return
	}
	// If there's no federation root and this isn't a nested request, this
	// isn't a federated field and there's nothing to do.
	if !p.hasFederationRoot && !p.isNestedRequest() {
		return
	}
	// If a federated root is already present, the representations variable has
	// already been added. Update it to include information for the additional
	// field. NOTE: only the first federated field has isNestedRequest set to
	// true. Subsequent fields use hasFederationRoot to determine federation
	// status.
	if p.hasFederationRoot {
		// Ideally the "representations" variable could be set once in
		// LeaveDocument, but ConfigureFetch is called before this visitor's
		// LeaveDocument is called. (Updating the visitor logic to call
		// LeaveDocument in reverse registration order would fix this issue.)
		p.updateRepresentationsVariable(fieldConfig)
		return
	}
	p.hasFederationRoot = true
	// query($representations: [_Any!]!){_entities(representations: $representations){... on Product
	p.addRepresentationsVariableDefinition()     // $representations: [_Any!]!
	p.addEntitiesSelectionSet()                  // {_entities(representations: $representations)
	p.addOneTypeInlineFragment()                 // ... on Product
	p.updateRepresentationsVariable(fieldConfig) // "variables\":{\"representations\":[{\"upc\":\"$$0$$\",\"__typename\":\"Product\"}]}}
}

func (p *Planner) updateRepresentationsVariable(fieldConfig *plan.FieldConfiguration) {
	// "variables\":{\"representations\":[{\"upc\":\$$0$$\,\"__typename\":\"Product\"}]}}
	parser := astparser.NewParser()
	doc := ast.NewDocument()
	doc.Input.ResetInputString(p.config.Federation.ServiceSDL)
	report := &operationreport.Report{}
	parser.Parse(doc, report)
	if report.HasErrors() {
		p.visitor.Walker.StopWithInternalErr(fmt.Errorf("GraphQL Planner: failed parsing Federation SDL"))
		return
	}

	// RequiresFields includes `@requires` fields as well as federation keys
	// for the type containing the field currently being visited.
	fields := fieldConfig.RequiresFields
	if len(fields) == 0 {
		return
	}

	onTypeName := p.visitor.Config.Types.RenameTypeNameOnMatchStr(p.lastFieldEnclosingTypeName)

	if len(p.representationsJson) == 0 {
		p.representationsJson, _ = sjson.SetRawBytes(nil, "__typename", []byte("\""+onTypeName+"\""))
	}

	for i := range fields {
		objectVariable := &resolve.ObjectVariable{
			Path: []string{fields[i]},
		}
		fieldDef := p.fieldDefinition(fields[i], p.lastFieldEnclosingTypeName)
		if fieldDef == nil {
			continue
		}
		renderer, err := resolve.NewJSONVariableRendererWithValidationFromTypeRef(p.visitor.Definition, p.visitor.Definition, fieldDef.Type)
		if err != nil {
			continue
		}
		objectVariable.Renderer = renderer
		variable, exists := p.variables.AddVariable(objectVariable)
		if exists {
			continue
		}
		p.representationsJson, _ = sjson.SetRawBytes(p.representationsJson, fields[i], []byte(variable))
	}
	representationsJson := append([]byte("["), append(p.representationsJson, []byte("]")...)...)
	p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, "representations", representationsJson)
	p.extractEntities = true
}

func (p *Planner) fieldDefinition(fieldName, typeName string) *ast.FieldDefinition {
	node, ok := p.visitor.Definition.Index.FirstNodeByNameStr(typeName)
	if !ok {
		return nil
	}
	definition, ok := p.visitor.Definition.NodeFieldDefinitionByName(node, []byte(fieldName))
	if !ok {
		return nil
	}
	return &p.visitor.Definition.FieldDefinitions[definition]
}

func (p *Planner) addOneTypeInlineFragment() {
	selectionSet := p.upstreamOperation.AddSelectionSet()
	onTypeName := p.visitor.Config.Types.RenameTypeNameOnMatchBytes([]byte(p.lastFieldEnclosingTypeName))
	typeRef := p.upstreamOperation.AddNamedType(onTypeName)
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
	nonNullAnyType := p.upstreamOperation.AddNonNullType(anyType)
	listOfNonNullAnyType := p.upstreamOperation.AddListType(nonNullAnyType)
	nonNullListOfNonNullAnyType := p.upstreamOperation.AddNonNullType(listOfNonNullAnyType)

	representationsVariable := p.upstreamOperation.ImportVariableValue([]byte("representations"))
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

func (p *Planner) storeArgType(typeName, fieldName, argName string) {
	typeNode, _ := p.visitor.Definition.Index.FirstNodeByNameStr(typeName)

	for _, fieldDefRef := range p.visitor.Definition.ObjectTypeDefinitions[typeNode.Ref].FieldsDefinition.Refs {
		if bytes.Equal(p.visitor.Definition.FieldDefinitionNameBytes(fieldDefRef), []byte(fieldName)) {
			for _, argDefRef := range p.visitor.Definition.FieldDefinitions[fieldDefRef].ArgumentsDefinition.Refs {
				if bytes.Equal(p.visitor.Definition.InputValueDefinitionNameBytes(argDefRef), []byte(argName)) {
					p.argTypeRef = p.visitor.Definition.ResolveListOrNameType(p.visitor.Definition.InputValueDefinitions[argDefRef].Type)
					return
				}
			}
		}
	}
}

func (p *Planner) configureArgument(upstreamFieldRef, downstreamFieldRef int, fieldConfig plan.FieldConfiguration, argumentConfiguration plan.ArgumentConfiguration) {
	p.storeArgType(fieldConfig.TypeName, fieldConfig.FieldName, argumentConfiguration.Name)

	switch argumentConfiguration.SourceType {
	case plan.FieldArgumentSource:
		p.configureFieldArgumentSource(upstreamFieldRef, downstreamFieldRef, argumentConfiguration.Name, argumentConfiguration.SourcePath)
	case plan.ObjectFieldSource:
		p.configureObjectFieldSource(upstreamFieldRef, downstreamFieldRef, fieldConfig, argumentConfiguration)
	}

	p.argTypeRef = -1
}

// configureFieldArgumentSource - creates variables for a plain argument types, in case object or list types goes deep and calls applyInlineFieldArgument
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

	fieldName := p.visitor.Operation.FieldNameBytes(downstreamFieldRef)
	argumentDefinition := p.visitor.Definition.NodeFieldDefinitionArgumentDefinitionByName(p.visitor.Walker.EnclosingTypeDefinition, fieldName, []byte(argumentName))

	if argumentDefinition == -1 {
		return
	}

	argumentType := p.visitor.Definition.InputValueDefinitionType(argumentDefinition)
	renderer, err := resolve.NewJSONVariableRendererWithValidationFromTypeRef(p.visitor.Definition, p.visitor.Definition, argumentType)
	if err != nil {
		return
	}

	contextVariable := &resolve.ContextVariable{
		Path:     []string{variableNameStr},
		Renderer: renderer,
	}

	contextVariableName, exists := p.variables.AddVariable(contextVariable)
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
		typeName := p.visitor.Operation.ResolveTypeNameString(p.visitor.Operation.VariableDefinitions[i].Type)
		typeName = p.visitor.Config.Types.RenameTypeNameOnMatchStr(typeName)
		importedType := p.visitor.Importer.ImportTypeWithRename(p.visitor.Operation.VariableDefinitions[i].Type, p.visitor.Operation, p.upstreamOperation, typeName)
		p.upstreamOperation.AddVariableDefinitionToOperationDefinition(p.nodes[0].Ref, variableValueRef, importedType)

		if add, ok := p.addDirectivesToVariableDefinitions[i]; ok {
			for _, directive := range add {
				p.addDirectiveToNode(directive, ast.Node{Kind: ast.NodeKindVariableDefinition, Ref: i})
			}
		}
	}

	p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, variableNameStr, []byte(contextVariableName))
}

// applyInlineFieldArgument - configures arguments for a complex argument of a list or input object type
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

	p.addVariableDefinitionsRecursively(value, sourcePath, nil)
}

// resolveNestedArgumentType - extracts type of nested field or array element of argument
// fieldName - exists only for ast.ValueKindObject type of argument
func (p *Planner) resolveNestedArgumentType(fieldName []byte) (fieldTypeRef int) {
	if fieldName == nil {
		return p.visitor.Definition.ResolveListOrNameType(p.argTypeRef)
	}

	argTypeName := p.visitor.Definition.ResolveTypeNameString(p.argTypeRef)
	argTypeNode, _ := p.visitor.Definition.Index.FirstNodeByNameStr(argTypeName)

	for _, inputFieldDefRef := range p.visitor.Definition.InputObjectTypeDefinitions[argTypeNode.Ref].InputFieldsDefinition.Refs {
		if bytes.Equal(p.visitor.Definition.InputValueDefinitionNameBytes(inputFieldDefRef), fieldName) {
			return p.visitor.Definition.ResolveListOrNameType(p.visitor.Definition.InputValueDefinitions[inputFieldDefRef].Type)
		}
	}

	return -1
}

// addVariableDefinitionsRecursively - recursively configures variables inside a list or an input type
func (p *Planner) addVariableDefinitionsRecursively(value ast.Value, sourcePath []string, fieldName []byte) {
	switch value.Kind {
	case ast.ValueKindObject:
		prevArgTypeRef := p.argTypeRef
		p.argTypeRef = p.resolveNestedArgumentType(fieldName)
		for _, objectFieldRef := range p.visitor.Operation.ObjectValues[value.Ref].Refs {
			p.addVariableDefinitionsRecursively(p.visitor.Operation.ObjectFields[objectFieldRef].Value, sourcePath, p.visitor.Operation.ObjectFieldNameBytes(objectFieldRef))
		}
		p.argTypeRef = prevArgTypeRef
		return
	case ast.ValueKindList:
		for _, i := range p.visitor.Operation.ListValues[value.Ref].Refs {
			p.addVariableDefinitionsRecursively(p.visitor.Operation.Values[i], sourcePath, nil)
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

	variableDefinitionTypeName := p.visitor.Operation.ResolveTypeNameString(p.visitor.Operation.VariableDefinitions[variableDefinition].Type)
	variableDefinitionTypeName = p.visitor.Config.Types.RenameTypeNameOnMatchStr(variableDefinitionTypeName)

	importedVariableDefinition := p.visitor.Importer.ImportVariableDefinitionWithRename(variableDefinition, p.visitor.Operation, p.upstreamOperation, variableDefinitionTypeName)
	p.upstreamOperation.AddImportedVariableDefinitionToOperationDefinition(p.nodes[0].Ref, importedVariableDefinition)

	fieldType := p.resolveNestedArgumentType(fieldName)
	contextVariable := &resolve.ContextVariable{
		Path: append(sourcePath, variableNameStr),
	}
	renderer, err := resolve.NewJSONVariableRendererWithValidationFromTypeRef(p.visitor.Definition, p.visitor.Definition, fieldType)
	if err != nil {
		return
	}
	contextVariable.Renderer = renderer
	contextVariableName, variableExists := p.variables.AddVariable(contextVariable)
	if variableExists {
		return
	}
	p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, variableNameStr, []byte(contextVariableName))
}

// configureObjectFieldSource - configures source of a field when it has variables coming from current object
func (p *Planner) configureObjectFieldSource(upstreamFieldRef, downstreamFieldRef int, fieldConfiguration plan.FieldConfiguration, argumentConfiguration plan.ArgumentConfiguration) {
	if len(argumentConfiguration.SourcePath) < 1 {
		return
	}

	fieldName := p.visitor.Operation.FieldNameUnsafeString(downstreamFieldRef)

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

	typeName := p.visitor.Operation.ResolveTypeNameString(argumentType)
	typeName = p.visitor.Config.Types.RenameTypeNameOnMatchStr(typeName)

	importedType := p.visitor.Importer.ImportTypeWithRename(argumentType, p.visitor.Definition, p.upstreamOperation, typeName)
	p.upstreamOperation.AddVariableDefinitionToOperationDefinition(p.nodes[0].Ref, variableValue, importedType)

	renderer, err := resolve.NewJSONVariableRendererWithValidationFromTypeRef(p.visitor.Definition, p.visitor.Definition, argumentType)
	if err != nil {
		return
	}

	variable := &resolve.ObjectVariable{
		Path:     argumentConfiguration.SourcePath,
		Renderer: renderer,
	}

	objectVariableName, exists := p.variables.AddVariable(variable)
	if !exists {
		p.upstreamVariables, _ = sjson.SetRawBytes(p.upstreamVariables, string(variableName), []byte(objectVariableName))
	}
}

const (
	normalizationFailedErrMsg = "printOperation: normalization failed"
	parseDocumentFailedErrMsg = "printOperation: parse %s failed"
)

// printOperation - prints normalized upstream operation
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

	if p.config.UpstreamSchema != "" {
		baseSchema = p.config.UpstreamSchema
	}

	federationSchema, err := federation.BuildFederationSchema(baseSchema, p.config.Federation.ServiceSDL)
	if err != nil {
		p.visitor.Walker.StopWithInternalErr(err)
		return nil
	}

	// create empty operation and definition documents
	operation := ast.NewDocument()
	definition := ast.NewDocument()
	report := &operationreport.Report{}
	operationParser := astparser.NewParser()
	definitionParser := astparser.NewParser()

	operation.Input.ResetInputBytes(rawQuery)
	operationParser.Parse(operation, report)
	if report.HasErrors() {
		p.stopWithError(parseDocumentFailedErrMsg, "operation")
		return nil
	}

	// creates a copy of operation and schema to be able to safely modify them
	// if an upstream schema was supplied, we use it to validate and normalize against
	// otherwise, normalization would fail because the downstream schema doesn't contain the upstream fields
	if !p.config.Federation.Enabled && p.config.UpstreamSchema != "" {
		definition.Input.ResetInputString(p.config.UpstreamSchema)
		definitionParser.Parse(definition, report)
		if report.HasErrors() {
			p.stopWithError("unable to parse upstream schema")
			return nil
		}
		if err := asttransform.MergeDefinitionWithBaseSchema(definition); err != nil {
			p.stopWithError("unable to merge upstream schema with base schema")
			return nil
		}
	} else {
		definition.Input.ResetInputString(federationSchema)
		definitionParser.Parse(definition, report)
		if report.HasErrors() {
			p.stopWithError(parseDocumentFailedErrMsg, "definition")
			return nil
		}
		if err := asttransform.MergeDefinitionWithBaseSchema(definition); err != nil {
			p.stopWithError("unable to merge upstream schema with base schema")
			return nil
		}
	}

	// When datasource is nested and definition query type do not contain operation field
	// we have to replace a query type with a current root type
	p.replaceQueryType(definition)

	// normalize upstream operation
	if !p.normalizeOperation(operation, definition, report) {
		p.stopWithError(normalizationFailedErrMsg)
		return nil
	}

	buf.Reset()

	// print upstream operation
	err = astprinter.Print(operation, p.visitor.Definition, buf)
	if err != nil {
		p.stopWithError(normalizationFailedErrMsg)
		return nil
	}

	return buf.Bytes()
}

func (p *Planner) stopWithError(msg string, args ...interface{}) {
	p.visitor.Walker.StopWithInternalErr(fmt.Errorf(msg, args...))
}

/*
replaceQueryType - sets definition query type to a current root type.
Helps to do a normalization of the upstream query for a nested datasource.
Skips replace when:
1. datasource is not nested;
2. federation is enabled;
3. query type contains an operation field;

Example transformation:
Original schema definition:

type Query {
	serviceOne(serviceOneArg: String): ServiceOneResponse
	serviceTwo(serviceTwoArg: Boolean): ServiceTwoResponse
}
type ServiceOneResponse {
	fieldOne: String!
	countries: [Country!]! # nested datasource without explicit field path
}
type ServiceTwoResponse {
	fieldTwo: String
	serviceOneField: String
	serviceOneResponse: ServiceOneResponse # nested datasource with implicit field path "serviceOne"
}
type Country {
	name: String!
}

`serviceOneResponse` field of a `ServiceTwoResponse` is nested but has a field path that exists on the Query type
- In this case definition will not be modified

`countries` field of a `ServiceOneResponse` is nested and not present on the Query type
- In this case query type of definition will be replaced with a `ServiceOneResponse`

Modified schema definition:

schema {
   query: ServiceOneResponse
}

type ServiceOneResponse {
   fieldOne: String!
   countries: [Country!]!
}

type ServiceTwoResponse {
   fieldTwo: String
   serviceOneField: String
   serviceOneResponse: ServiceOneResponse
}

type Country {
   name: String!
}
Refer to pkg/engine/datasource/graphql_datasource/graphql_datasource_test.go:632
Case name: TestGraphQLDataSource/nested_graphql_engines

If we didn't do this transformation, the normalization would fail because it's not possible
to traverse the AST as there's a mismatch between the upstream Operation and the schema.

If the nested Query can be rewritten so that it's a valid Query against the existing schema, fine.
However, when rewriting the nested Query onto the schema's Query type,
it might be the case that no FieldDefinition exists for the rewritten root field.
In that case, we transform the schema so that normalization and printing of the upstream Query succeeds.
*/
func (p *Planner) replaceQueryType(definition *ast.Document) {
	if !p.isNested || p.config.Federation.Enabled {
		return
	}

	queryTypeName := definition.Index.QueryTypeName
	queryNode, exists := definition.Index.FirstNodeByNameBytes(queryTypeName)
	if !exists || queryNode.Kind != ast.NodeKindObjectTypeDefinition {
		return
	}

	// check that query type has rootFieldName within its fields
	hasField := definition.FieldDefinitionsContainField(definition.ObjectTypeDefinitions[queryNode.Ref].FieldsDefinition.Refs, []byte(p.rootFieldName))
	if hasField {
		return
	}

	definition.RemoveObjectTypeDefinition(definition.Index.QueryTypeName)
	definition.ReplaceRootOperationTypeDefinition(p.rootTypeName, ast.OperationTypeQuery)
}

// normalizeOperation - normalizes operation against definition.
func (p *Planner) normalizeOperation(operation, definition *ast.Document, report *operationreport.Report) (ok bool) {
	report.Reset()
	normalizer := astnormalization.NewWithOpts(
		astnormalization.WithExtractVariables(),
		astnormalization.WithRemoveFragmentDefinitions(),
		astnormalization.WithRemoveUnusedVariables(),
	)
	normalizer.NormalizeOperation(operation, definition, report)

	return !report.HasErrors()
}

// addField - add a field to an upstream operation
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
		isDesiredField := p.visitor.Config.Fields[i].TypeName == typeName &&
			p.visitor.Config.Fields[i].FieldName == fieldName

		// check that we are on a desired field and field path contains a single element - mapping is plain
		if isDesiredField && len(p.visitor.Config.Fields[i].Path) == 1 {
			// define alias when mapping path differs from fieldName and no alias has been defined
			if p.visitor.Config.Fields[i].Path[0] != fieldName && !alias.IsDefined {
				alias.IsDefined = true
				aliasBytes := p.visitor.Operation.FieldNameBytes(ref)
				alias.Name = p.upstreamOperation.Input.AppendInputBytes(aliasBytes)
			}

			// override fieldName with mapping path value
			fieldName = p.visitor.Config.Fields[i].Path[0]

			// when provided field is a root type field save new field name
			if ref == p.rootFieldRef {
				p.rootFieldName = fieldName
			}

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
	BatchFactory resolve.DataSourceBatchFactory
	HTTPClient   *http.Client
	wsClient     *WebSocketGraphQLSubscriptionClient
}

func (f *Factory) Planner(ctx context.Context) plan.DataSourcePlanner {
	if f.wsClient == nil {
		f.wsClient = NewWebSocketGraphQLSubscriptionClient(f.HTTPClient, ctx)
	}
	return &Planner{
		batchFactory:       f.BatchFactory,
		fetchClient:        f.HTTPClient,
		subscriptionClient: f.wsClient,
	}
}

type Source struct {
	httpClient *http.Client
}

func (s *Source) Load(ctx context.Context, input []byte, writer io.Writer) (err error) {
	return httpclient.Do(s.httpClient, ctx, input, writer)
}

type GraphQLSubscriptionClient interface {
	Subscribe(ctx context.Context, options GraphQLSubscriptionOptions, next chan<- []byte) error
}

type GraphQLSubscriptionOptions struct {
	URL    string      `json:"url"`
	Body   GraphQLBody `json:"body"`
	Header http.Header `json:"header"`
}

type GraphQLBody struct {
	Query         string          `json:"query,omitempty"`
	OperationName string          `json:"operationName,omitempty"`
	Variables     json.RawMessage `json:"variables,omitempty"`
}

type SubscriptionSource struct {
	client GraphQLSubscriptionClient
}

func (s *SubscriptionSource) Start(ctx context.Context, input []byte, next chan<- []byte) error {
	var options GraphQLSubscriptionOptions
	err := json.Unmarshal(input, &options)
	if err != nil {
		return err
	}
	if options.Body.Query == "" {
		return resolve.ErrUnableToResolve
	}
	return s.client.Subscribe(ctx, options, next)
}
