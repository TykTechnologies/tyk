package datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/buger/jsonparser"
	"github.com/cespare/xxhash"
	log "github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astimport"
	"github.com/jensneuse/graphql-go-tools/pkg/astprinter"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

var graphqlSchemes = []string{
	"https",
	"http",
}

type GraphqlRequest struct {
	OperationName string          `json:"operationName"`
	Variables     json.RawMessage `json:"variables"`
	Query         string          `json:"query"`
}

// GraphQLDataSourceConfig is the configuration for the GraphQL DataSource
type GraphQLDataSourceConfig struct {
	// URL is the url of the upstream
	URL string `bson:"url" json:"url"`
	// Method is the http.Method of the upstream, defaults to POST (optional)
	Method *string `bson:"method" json:"method"`
}

type GraphQLDataSourcePlanner struct {
	BasePlanner
	importer                     *astimport.Importer
	nodes                        []ast.Node
	resolveDocument              *ast.Document
	dataSourceConfiguration      GraphQLDataSourceConfig
	client                       *http.Client
	whitelistedSchemes           []string
	whitelistedVariableRefs      []int
	whitelistedVariableNameHashs map[uint64]bool
	hooks                        Hooks
}

type GraphQLDataSourcePlannerFactoryFactory struct {
	Client             *http.Client
	WhitelistedSchemes []string
	Hooks              Hooks
}

func (g *GraphQLDataSourcePlannerFactoryFactory) httpClient() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return DefaultHttpClient()
}

func (g GraphQLDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := &GraphQLDataSourcePlannerFactory{
		base:               base,
		client:             g.httpClient(),
		whitelistedSchemes: g.WhitelistedSchemes,
		hooks:              g.Hooks,
	}
	err := json.NewDecoder(configReader).Decode(&factory.config)
	return factory, err
}

type GraphQLDataSourcePlannerFactory struct {
	base               BasePlanner
	config             GraphQLDataSourceConfig
	client             *http.Client
	whitelistedSchemes []string
	hooks              Hooks
}

func (g *GraphQLDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return &GraphQLDataSourcePlanner{
		BasePlanner:                  g.base,
		importer:                     &astimport.Importer{},
		dataSourceConfiguration:      g.config,
		resolveDocument:              &ast.Document{},
		client:                       g.client,
		whitelistedSchemes:           g.whitelistedSchemes,
		whitelistedVariableRefs:      []int{},
		whitelistedVariableNameHashs: map[uint64]bool{},
		hooks:                        g.hooks,
	}
}

func (g *GraphQLDataSourcePlanner) EnterDocument(operation, definition *ast.Document) {
	g.whitelistedVariableRefs = g.whitelistedVariableRefs[:0]
}

func (g *GraphQLDataSourcePlanner) EnterInlineFragment(ref int) {
	if len(g.nodes) == 0 {
		return
	}
	current := g.nodes[len(g.nodes)-1]
	if current.Kind != ast.NodeKindSelectionSet {
		return
	}
	inlineFragmentType := g.importer.ImportType(g.Operation.InlineFragments[ref].TypeCondition.Type, g.Operation, g.resolveDocument)
	g.resolveDocument.InlineFragments = append(g.resolveDocument.InlineFragments, ast.InlineFragment{
		TypeCondition: ast.TypeCondition{
			Type: inlineFragmentType,
		},
		SelectionSet: -1,
	})
	inlineFragmentRef := len(g.resolveDocument.InlineFragments) - 1
	g.resolveDocument.Selections = append(g.resolveDocument.Selections, ast.Selection{
		Kind: ast.SelectionKindInlineFragment,
		Ref:  inlineFragmentRef,
	})
	selectionRef := len(g.resolveDocument.Selections) - 1
	g.resolveDocument.SelectionSets[current.Ref].SelectionRefs = append(g.resolveDocument.SelectionSets[current.Ref].SelectionRefs, selectionRef)
	g.nodes = append(g.nodes, ast.Node{
		Kind: ast.NodeKindInlineFragment,
		Ref:  inlineFragmentRef,
	})
}

func (g *GraphQLDataSourcePlanner) LeaveInlineFragment(ref int) {
	g.nodes = g.nodes[:len(g.nodes)-1]
}

func (g *GraphQLDataSourcePlanner) EnterSelectionSet(ref int) {

	fieldOrInlineFragment := g.nodes[len(g.nodes)-1]

	set := ast.SelectionSet{}
	g.resolveDocument.SelectionSets = append(g.resolveDocument.SelectionSets, set)
	setRef := len(g.resolveDocument.SelectionSets) - 1

	switch fieldOrInlineFragment.Kind {
	case ast.NodeKindField:
		g.resolveDocument.Fields[fieldOrInlineFragment.Ref].HasSelections = true
		g.resolveDocument.Fields[fieldOrInlineFragment.Ref].SelectionSet = setRef
	case ast.NodeKindInlineFragment:
		g.resolveDocument.InlineFragments[fieldOrInlineFragment.Ref].HasSelections = true
		g.resolveDocument.InlineFragments[fieldOrInlineFragment.Ref].SelectionSet = setRef
	}

	g.nodes = append(g.nodes, ast.Node{
		Kind: ast.NodeKindSelectionSet,
		Ref:  setRef,
	})
}

func (g *GraphQLDataSourcePlanner) LeaveSelectionSet(ref int) {
	g.nodes = g.nodes[:len(g.nodes)-1]
}

func (g *GraphQLDataSourcePlanner) EnterField(ref int) {
	if !g.RootField.isDefined {
		g.RootField.SetIfNotDefined(ref)

		typeName := g.Definition.NodeNameString(g.Walker.EnclosingTypeDefinition)
		fieldNameStr := g.Operation.FieldNameString(ref)
		fieldName := g.Operation.FieldNameBytes(ref)

		g.Args = append(g.Args, &StaticVariableArgument{
			Name:  RootTypeName,
			Value: []byte(typeName),
		})

		g.Args = append(g.Args, &StaticVariableArgument{
			Name:  RootFieldName,
			Value: fieldName,
		})

		mapping := g.Config.MappingForTypeField(typeName, fieldNameStr)
		if mapping != nil && !mapping.Disabled {
			fieldName = unsafebytes.StringToBytes(mapping.Path)
		}

		hasArguments := g.Operation.FieldHasArguments(ref)
		var argumentRefs []int
		if hasArguments {
			argumentRefs = g.importer.ImportArguments(g.Operation.FieldArguments(ref), g.Operation, g.resolveDocument)
		}

		field := ast.Field{
			Name: g.resolveDocument.Input.AppendInputBytes(fieldName),
			Arguments: ast.ArgumentList{
				Refs: argumentRefs,
			},
			HasArguments: hasArguments,
		}
		g.resolveDocument.Fields = append(g.resolveDocument.Fields, field)
		fieldRef := len(g.resolveDocument.Fields) - 1
		selection := ast.Selection{
			Kind: ast.SelectionKindField,
			Ref:  fieldRef,
		}
		g.resolveDocument.Selections = append(g.resolveDocument.Selections, selection)
		selectionRef := len(g.resolveDocument.Selections) - 1
		set := ast.SelectionSet{
			SelectionRefs: []int{selectionRef},
		}
		g.resolveDocument.SelectionSets = append(g.resolveDocument.SelectionSets, set)
		setRef := len(g.resolveDocument.SelectionSets) - 1
		operationDefinition := ast.OperationDefinition{
			Name:          g.resolveDocument.Input.AppendInputBytes([]byte("o")),
			OperationType: g.Operation.OperationDefinitions[g.Walker.Ancestors[0].Ref].OperationType,
			SelectionSet:  setRef,
			HasSelections: true,
		}
		g.resolveDocument.OperationDefinitions = append(g.resolveDocument.OperationDefinitions, operationDefinition)
		operationDefinitionRef := len(g.resolveDocument.OperationDefinitions) - 1
		g.resolveDocument.RootNodes = append(g.resolveDocument.RootNodes, ast.Node{
			Kind: ast.NodeKindOperationDefinition,
			Ref:  operationDefinitionRef,
		})
		g.nodes = append(g.nodes, ast.Node{
			Kind: ast.NodeKindOperationDefinition,
			Ref:  operationDefinitionRef,
		})
		g.nodes = append(g.nodes, ast.Node{
			Kind: ast.NodeKindSelectionSet,
			Ref:  setRef,
		})
		g.nodes = append(g.nodes, ast.Node{
			Kind: ast.NodeKindField,
			Ref:  fieldRef,
		})
	} else {
		field := ast.Field{
			Name: g.resolveDocument.Input.AppendInputBytes(g.Operation.FieldNameBytes(ref)),
		}
		g.resolveDocument.Fields = append(g.resolveDocument.Fields, field)
		fieldRef := len(g.resolveDocument.Fields) - 1
		set := g.nodes[len(g.nodes)-1]
		selection := ast.Selection{
			Kind: ast.SelectionKindField,
			Ref:  fieldRef,
		}
		g.resolveDocument.Selections = append(g.resolveDocument.Selections, selection)
		selectionRef := len(g.resolveDocument.Selections) - 1
		g.resolveDocument.SelectionSets[set.Ref].SelectionRefs = append(g.resolveDocument.SelectionSets[set.Ref].SelectionRefs, selectionRef)
		g.nodes = append(g.nodes, ast.Node{
			Kind: ast.NodeKindField,
			Ref:  fieldRef,
		})
	}
}

func (g *GraphQLDataSourcePlanner) EnterArgument(ref int) {
	variableValue := g.Operation.ArgumentValue(ref)
	if variableValue.Kind != ast.ValueKindVariable {
		return
	}

	variableName := g.Operation.VariableValueNameBytes(variableValue.Ref)
	definitionRef, exists := g.Operation.VariableDefinitionByNameAndOperation(g.nodes[0].Ref, variableName)
	if !exists {
		return
	}

	g.whitelistedVariableRefs = append(g.whitelistedVariableRefs, definitionRef)
	g.whitelistedVariableNameHashs[xxhash.Sum64(variableName)] = true
}

func (g *GraphQLDataSourcePlanner) LeaveField(ref int) {
	defer func() {
		g.nodes = g.nodes[:len(g.nodes)-1]
	}()
	if g.RootField.ref != ref {
		return
	}

	hasVariableDefinitions := len(g.Operation.OperationDefinitions[g.Walker.Ancestors[0].Ref].VariableDefinitions.Refs) != 0
	var variableDefinitionsRefs []int
	if hasVariableDefinitions {
		operationVariableDefinitions := g.Operation.OperationDefinitions[g.Walker.Ancestors[0].Ref].VariableDefinitions.Refs
		definitions := make([]int, len(operationVariableDefinitions))
		copy(definitions, operationVariableDefinitions)
		definitions = ast.FilterIntSliceByWhitelist(definitions, g.whitelistedVariableRefs)

		variableDefinitionsRefs = g.importer.ImportVariableDefinitions(definitions, g.Operation, g.resolveDocument)
		g.resolveDocument.OperationDefinitions[0].HasVariableDefinitions = len(definitions) != 0
		g.resolveDocument.OperationDefinitions[0].VariableDefinitions.Refs = variableDefinitionsRefs
	}

	buff := bytes.Buffer{}
	err := astprinter.Print(g.resolveDocument, nil, &buff)
	if err != nil {
		g.Walker.StopWithInternalErr(err)
		return
	}
	g.Args = append(g.Args, &StaticVariableArgument{
		Name:  literal.URL,
		Value: []byte(g.dataSourceConfiguration.URL),
	})
	g.Args = append(g.Args, &StaticVariableArgument{
		Name:  literal.QUERY,
		Value: buff.Bytes(),
	})
	if g.dataSourceConfiguration.Method == nil {
		g.Args = append(g.Args, &StaticVariableArgument{
			Name:  literal.METHOD,
			Value: literal.HTTP_METHOD_POST,
		})
	} else {
		g.Args = append(g.Args, &StaticVariableArgument{
			Name:  literal.URL,
			Value: []byte(*g.dataSourceConfiguration.Method),
		})
	}
}

func (g *GraphQLDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {
	for i := range args {
		if arg, ok := args[i].(*ContextVariableArgument); ok {
			if bytes.HasPrefix(arg.Name, literal.DOT_ARGUMENTS_DOT) {
				arg.Name = bytes.TrimPrefix(arg.Name, literal.DOT_ARGUMENTS_DOT)

				if g.whitelistedVariableNameHashs[xxhash.Sum64(arg.Name)] {
					g.Args = append(g.Args, arg)
				} else if g.whitelistedVariableNameHashs[xxhash.Sum64(arg.VariableName)] {
					arg.Name = arg.VariableName
					g.Args = append(g.Args, arg)
				}
			}
		}
	}
	return &GraphQLDataSource{
		Log:                g.Log,
		Client:             g.client,
		WhitelistedSchemes: g.whitelistedSchemes,
		Hooks:              g.hooks,
	}, g.Args
}

type GraphQLDataSource struct {
	Log                log.Logger
	Client             *http.Client
	WhitelistedSchemes []string
	Hooks              Hooks
}

func (g *GraphQLDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {
	urlArg := args.ByKey(literal.URL)
	queryArg := args.ByKey(literal.QUERY)
	rootTypeName := args.ByKey(RootTypeName)
	rootFieldName := args.ByKey(RootFieldName)
	hookContext := HookContext{
		TypeName:  string(rootTypeName),
		FieldName: string(rootFieldName),
	}

	g.Log.Debug("GraphQLDataSource.Resolve.Args",
		log.Strings("resolvedArgs", args.Dump()),
	)

	if urlArg == nil || queryArg == nil {
		g.Log.Error("GraphQLDataSource.Args invalid")
		return
	}

	parsedURL, rawURL, err := parseURLBytes(urlArg)
	if err != nil {
		g.Log.Error("GraphQLDataSource.RawURL could not be parsed", log.String("rawURL", rawURL))
		return
	}

	if len(parsedURL.Scheme) == 0 || !isWhitelistedScheme(parsedURL.Scheme, g.WhitelistedSchemes, graphqlSchemes) {
		parsedURL.Scheme = graphqlSchemes[0]
	}

	variables := map[string]interface{}{}
	keys := args.Keys()
	for i := 0; i < len(keys); i++ {
		switch {
		case bytes.Equal(keys[i], literal.URL):
		case bytes.Equal(keys[i], literal.QUERY):
		case bytes.Equal(keys[i], RootTypeName):
		case bytes.Equal(keys[i], RootFieldName):
		default:
			variables[string(keys[i])] = string(args.ByKey(keys[i]))
		}
	}

	variablesJson, err := json.Marshal(variables)
	if err != nil {
		g.Log.Error("GraphQLDataSource.json.Marshal(variables)",
			log.Error(err),
		)
		return n, err
	}

	gqlRequest := GraphqlRequest{
		OperationName: "o",
		Variables:     variablesJson,
		Query:         string(queryArg),
	}

	gqlRequestData, err := json.MarshalIndent(gqlRequest, "", "  ")
	if err != nil {
		g.Log.Error("GraphQLDataSource.json.MarshalIndent",
			log.Error(err),
		)
		return n, err
	}

	g.Log.Debug("GraphQLDataSource.request",
		log.String("rawURL", rawURL),
		log.String("parsedURL", parsedURL.String()),
		log.ByteString("data", gqlRequestData),
	)

	request, err := http.NewRequest(http.MethodPost, parsedURL.String(), bytes.NewBuffer(gqlRequestData))
	if err != nil {
		g.Log.Error("GraphQLDataSource.http.NewRequest",
			log.Error(err),
		)
		return n, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	if g.Hooks.PreSendHttpHook != nil {
		g.Hooks.PreSendHttpHook.Execute(hookContext, request)
	}

	res, err := g.Client.Do(request)
	if err != nil {
		g.Log.Error("GraphQLDataSource.client.Do",
			log.Error(err),
		)
		return n, err
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		g.Log.Error("GraphQLDataSource.ioutil.ReadAll",
			log.Error(err),
		)
		return n, err
	}

	if g.Hooks.PostReceiveHttpHook != nil {
		g.Hooks.PostReceiveHttpHook.Execute(hookContext, res, data)
	}

	defer func() {
		err := res.Body.Close()
		if err != nil {
			g.Log.Error("GraphQLDataSource.Resolve.Response.Body.Close", log.Error(err))
		}
	}()

	data = bytes.ReplaceAll(data, literal.BACKSLASH, nil)
	data, _, _, err = jsonparser.Get(data, "data")
	if err != nil {
		g.Log.Error("GraphQLDataSource.jsonparser.Get",
			log.Error(err),
		)
		return n, err
	}
	return out.Write(data)
}
