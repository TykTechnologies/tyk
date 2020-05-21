package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type TykInternalDataSourcePlannerFactoryFactory struct {
	logger *logrus.Logger
}

func (t *TykInternalDataSourcePlannerFactoryFactory) Initialize(base datasource.BasePlanner, configReader io.Reader) (datasource.PlannerFactory, error) {
	factory := &TykInternalDataSourcePlannerFactory{
		base:   base,
		logger: t.logger,
	}

	err := json.NewDecoder(configReader).Decode(&factory.config)
	if err != nil {
		return nil, err
	}

	apiNameOrID, err := url.Parse(factory.config.Host)
	if err != nil {
		return nil, err
	}

	factory.config.Host = apiNameOrID.Host

	return factory, err
}

type TykInternalDataSourcePlannerFactory struct {
	base   datasource.BasePlanner
	config datasource.HttpJsonDataSourceConfig
	logger *logrus.Logger
}

func (t *TykInternalDataSourcePlannerFactory) DataSourcePlanner() datasource.Planner {
	return &TykInternalDataSourcePlanner{
		BasePlanner:      t.base,
		dataSourceConfig: t.config,
		logger:           t.logger,
	}
}

type TykInternalDataSourcePlanner struct {
	datasource.BasePlanner
	dataSourceConfig datasource.HttpJsonDataSourceConfig
	logger           *logrus.Logger
}

func (t *TykInternalDataSourcePlanner) Plan(args []datasource.Argument) (datasource.DataSource, []datasource.Argument) {
	return &TykInternalDataSource{
		logger: t.logger,
	}, append(t.Args, args...)
}

func (t *TykInternalDataSourcePlanner) Configure(operation, definition *ast.Document, walker *astvisitor.Walker) {
	t.BasePlanner.Configure(operation, definition, walker)
}

func (t *TykInternalDataSourcePlanner) EnterInlineFragment(ref int) {

}

func (t *TykInternalDataSourcePlanner) LeaveInlineFragment(ref int) {

}

func (t *TykInternalDataSourcePlanner) EnterSelectionSet(ref int) {

}

func (t *TykInternalDataSourcePlanner) LeaveSelectionSet(ref int) {

}

func (t *TykInternalDataSourcePlanner) EnterField(ref int) {
	t.RootField.SetIfNotDefined(ref)
}

func (t *TykInternalDataSourcePlanner) LeaveField(ref int) {
	if !t.RootField.IsDefinedAndEquals(ref) {
		return
	}
	definition, exists := t.Walker.FieldDefinition(ref)
	if !exists {
		return
	}
	t.Args = append(t.Args, &datasource.StaticVariableArgument{
		Name:  literal.HOST,
		Value: []byte(t.dataSourceConfig.Host),
	})
	t.Args = append(t.Args, &datasource.StaticVariableArgument{
		Name:  literal.URL,
		Value: []byte(t.dataSourceConfig.URL),
	})
	if t.dataSourceConfig.Method == nil {
		t.Args = append(t.Args, &datasource.StaticVariableArgument{
			Name:  literal.METHOD,
			Value: literal.HTTP_METHOD_GET,
		})
	} else {
		t.Args = append(t.Args, &datasource.StaticVariableArgument{
			Name:  literal.METHOD,
			Value: []byte(*t.dataSourceConfig.Method),
		})
	}
	if t.dataSourceConfig.Body != nil {
		t.Args = append(t.Args, &datasource.StaticVariableArgument{
			Name:  literal.BODY,
			Value: []byte(*t.dataSourceConfig.Body),
		})
	}

	if len(t.dataSourceConfig.Headers) != 0 {
		listArg := &datasource.ListArgument{
			Name: literal.HEADERS,
		}
		for i := range t.dataSourceConfig.Headers {
			listArg.Arguments = append(listArg.Arguments, &datasource.StaticVariableArgument{
				Name:  []byte(t.dataSourceConfig.Headers[i].Key),
				Value: []byte(t.dataSourceConfig.Headers[i].Value),
			})
		}
		t.Args = append(t.Args, listArg)
	}

	// __typename
	var typeNameValue []byte
	var err error
	fieldDefinitionTypeNode := t.Definition.FieldDefinitionTypeNode(definition)
	fieldDefinitionType := t.Definition.FieldDefinitionType(definition)
	fieldDefinitionTypeName := t.Definition.ResolveTypeNameBytes(fieldDefinitionType)
	quotedFieldDefinitionTypeName := append(literal.QUOTE, append(fieldDefinitionTypeName, literal.QUOTE...)...)
	switch fieldDefinitionTypeNode.Kind {
	case ast.NodeKindScalarTypeDefinition:
		return
	case ast.NodeKindUnionTypeDefinition, ast.NodeKindInterfaceTypeDefinition:
		if t.dataSourceConfig.DefaultTypeName != nil {
			typeNameValue, err = sjson.SetRawBytes(typeNameValue, "defaultTypeName", []byte("\""+*t.dataSourceConfig.DefaultTypeName+"\""))
			if err != nil {
				t.logger.WithError(err).Error("TykInternalDataSource set defaultTypeName (switch case union/interface)")
				return
			}
		}
		for i := range t.dataSourceConfig.StatusCodeTypeNameMappings {
			typeNameValue, err = sjson.SetRawBytes(typeNameValue, strconv.Itoa(t.dataSourceConfig.StatusCodeTypeNameMappings[i].StatusCode), []byte("\""+t.dataSourceConfig.StatusCodeTypeNameMappings[i].TypeName+"\""))
			if err != nil {
				t.logger.WithError(err).Error("TykInternalDataSource set statusCodeTypeMapping")
				return
			}
		}
	default:
		typeNameValue, err = sjson.SetRawBytes(typeNameValue, "defaultTypeName", quotedFieldDefinitionTypeName)
		if err != nil {
			t.logger.WithError(err).Error("TykInternalDataSource set defaultTypeName (switch case default)")
			return
		}
	}
	t.Args = append(t.Args, &datasource.StaticVariableArgument{
		Name:  literal.TYPENAME,
		Value: typeNameValue,
	})
}

type TykInternalDataSource struct {
	logger *logrus.Logger
}

func (t *TykInternalDataSource) Resolve(ctx context.Context, args datasource.ResolverArgs, out io.Writer) (n int, err error) {
	apiNameOrIDArg := args.ByKey(literal.HOST)
	methodArg := args.ByKey(literal.METHOD)
	urlArg := args.ByKey(literal.URL)
	typeNameArg := args.ByKey(literal.TYPENAME)

	t.logger.Debug("TykInternalDataSource Resolver Args", "args", args.Dump())

	switch {
	case len(apiNameOrIDArg) == 0:
		t.logger.Error("api name or id should not be empty or nil")
		return
	case len(methodArg) == 0:
		t.logger.Error("method should not be empty or nil")
		return
	case len(urlArg) == 0:
		t.logger.Error("url should not be empty or nil")
		return
	}

	httpMethod := http.MethodGet
	switch {
	case bytes.Equal(methodArg, literal.HTTP_METHOD_GET):
		httpMethod = http.MethodGet
	case bytes.Equal(methodArg, literal.HTTP_METHOD_POST):
		httpMethod = http.MethodPost
	case bytes.Equal(methodArg, literal.HTTP_METHOD_PUT):
		httpMethod = http.MethodPut
	case bytes.Equal(methodArg, literal.HTTP_METHOD_DELETE):
		httpMethod = http.MethodDelete
	case bytes.Equal(methodArg, literal.HTTP_METHOD_PATCH):
		httpMethod = http.MethodPatch
	}

	fullURL := fmt.Sprintf("tyk://%s%s", string(apiNameOrIDArg), string(urlArg))
	request, err := http.NewRequest(httpMethod, fullURL, nil)
	if err != nil {
		t.logger.WithError(err).Error("could not create request")
		return
	}

	handler, found := findInternalHttpHandlerByNameOrID(string(apiNameOrIDArg))
	if !found {
		t.logger.Error("handler for api name or id could not be found", "api name or id", apiNameOrIDArg)
		return
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	resp := recorder.Result()

	var data []byte

	if resp != nil {
		data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			t.logger.WithError(err).Error("could not read data source response")
			return
		}
	}

	statusCode := strconv.Itoa(recorder.Code)
	statusCodeTypeName := gjson.GetBytes(typeNameArg, statusCode)
	if statusCodeTypeName.Exists() {
		data, err = sjson.SetRawBytes(data, "__typename", []byte(statusCodeTypeName.Raw))
		if err != nil {
			t.logger.WithError(err).Error("could not write data from internal data source")
			return
		}
	} else {
		defaultTypeName := gjson.GetBytes(typeNameArg, "defaultTypeName")
		if defaultTypeName.Exists() {
			data, err = sjson.SetRawBytes(data, "__typename", []byte(defaultTypeName.Raw))
			if err != nil {
				t.logger.WithError(err).Error("could not write data from internal data source")
				return
			}
		}
	}

	return out.Write(data)
}
