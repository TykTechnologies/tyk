package datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/asttransform"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

var RootTypeName = []byte("root_type_name")
var RootFieldName = []byte("root_field_name")

var defaultHttpClient *http.Client

func DefaultHttpClient() *http.Client {
	if defaultHttpClient == nil {
		defaultHttpClient = &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 1024,
				TLSHandshakeTimeout: 0 * time.Second,
			},
		}
	}

	return defaultHttpClient
}

type ResolverArgs interface {
	ByKey(key []byte) []byte
	Dump() []string
	Keys() [][]byte
}

type DataSource interface {
	Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error)
}

type Planner interface {
	CorePlanner
	PlannerVisitors
}

type CorePlanner interface {
	// Plan plan returns the pre configured DataSource as well as the Arguments
	// During runtime the arguments get resolved and passed to the DataSource
	Plan(args []Argument) (DataSource, []Argument)
	// Configure is the function to initialize all important values for the Planner to function correctly
	// You probably need access to the Walker, Operation and ObjectDefinition to use the Planner to its full power
	// Walker gives you useful information from within all visitor Callbacks, e.g. the Path & Ancestors
	// Operation is the AST of the GraphQL Operation
	// ObjectDefinition is the AST of the GraphQL schema ObjectDefinition
	// Args are the pre-calculated Arguments from the planner
	// resolverParameters are the parameters from the @directive params field
	Configure(operation, definition *ast.Document, walker *astvisitor.Walker)
}

type PlannerVisitors interface {
	astvisitor.EnterDocumentVisitor
	astvisitor.EnterInlineFragmentVisitor
	astvisitor.LeaveInlineFragmentVisitor
	astvisitor.EnterSelectionSetVisitor
	astvisitor.LeaveSelectionSetVisitor
	astvisitor.EnterFieldVisitor
	astvisitor.EnterArgumentVisitor
	astvisitor.LeaveFieldVisitor
}

type PlannerFactory interface {
	DataSourcePlanner() Planner
}

type PlannerFactoryFactory interface {
	Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error)
}

type BasePlanner struct {
	Log                   abstractlogger.Logger
	Walker                *astvisitor.Walker   // nolint
	Definition, Operation *ast.Document        // nolint
	Args                  []Argument           // nolint
	RootField             rootField            // nolint
	Config                PlannerConfiguration // nolint
}

func NewBaseDataSourcePlanner(schema []byte, config PlannerConfiguration, logger abstractlogger.Logger) (*BasePlanner, error) {
	definition, report := astparser.ParseGraphqlDocumentBytes(schema)
	if report.HasErrors() {
		return nil, report
	}

	err := asttransform.MergeDefinitionWithBaseSchema(&definition)
	if err != nil {
		return nil, err
	}

	return &BasePlanner{
		Config:     config,
		Log:        logger,
		Definition: &definition,
	}, nil
}

func (b *BasePlanner) Configure(operation, definition *ast.Document, walker *astvisitor.Walker) {
	b.Operation, b.Definition, b.Walker = operation, definition, walker
}

func (b *BasePlanner) RegisterDataSourcePlannerFactory(dataSourceName string, factory PlannerFactoryFactory) (err error) {
	for i := range b.Config.TypeFieldConfigurations {
		if dataSourceName != b.Config.TypeFieldConfigurations[i].DataSource.Name {
			continue
		}
		configReader := bytes.NewReader(b.Config.TypeFieldConfigurations[i].DataSource.Config)
		b.Config.TypeFieldConfigurations[i].DataSourcePlannerFactory, err = factory.Initialize(*b, configReader)
		if err != nil {
			return err
		}
	}
	return nil
}

type PlannerConfiguration struct {
	TypeFieldConfigurations []TypeFieldConfiguration
}

type TypeFieldConfiguration struct {
	TypeName                 string                `bson:"type_name" json:"type_name"`
	FieldName                string                `bson:"field_name" json:"field_name"`
	Mapping                  *MappingConfiguration `bson:"mapping" json:"mapping"`
	DataSource               SourceConfig          `bson:"data_source" json:"data_source"`
	DataSourcePlannerFactory PlannerFactory        `bson:"-" json:"-"`
}

type SourceConfig struct {
	// Kind defines the unique identifier of the DataSource
	// Kind needs to match to the Planner "DataSourceName" name
	Name string `bson:"kind" json:"kind"`
	// Config is the DataSource specific configuration object
	// Each Planner needs to make sure to parse their Config Object correctly
	Config json.RawMessage `bson:"data_source_config" json:"data_source_config"`
}

type MappingConfiguration struct {
	Disabled bool   `bson:"disabled" json:"disabled"`
	Path     string `bson:"path" json:"path"`
}

func (p *PlannerConfiguration) DataSourcePlannerFactoryForTypeField(typeName, fieldName string) PlannerFactory {
	for i := range p.TypeFieldConfigurations {
		if strings.EqualFold(p.TypeFieldConfigurations[i].TypeName, typeName) && strings.EqualFold(p.TypeFieldConfigurations[i].FieldName, fieldName) {
			return p.TypeFieldConfigurations[i].DataSourcePlannerFactory
		}
	}
	return nil
}

func (p *PlannerConfiguration) MappingForTypeField(typeName, fieldName string) *MappingConfiguration {
	for i := range p.TypeFieldConfigurations {
		if strings.EqualFold(p.TypeFieldConfigurations[i].TypeName, typeName) && strings.EqualFold(p.TypeFieldConfigurations[i].FieldName, fieldName) {
			return p.TypeFieldConfigurations[i].Mapping
		}
	}
	return nil
}

type rootField struct {
	isDefined bool
	ref       int
}

func (r *rootField) SetIfNotDefined(ref int) {
	if r.isDefined {
		return
	}
	r.isDefined = true
	r.ref = ref
}

func (r *rootField) IsDefinedAndEquals(ref int) bool {
	return r.isDefined && r.ref == ref
}

type visitingDataSourcePlanner struct {
	CorePlanner
}

func (_ visitingDataSourcePlanner) EnterDocument(operation, definition *ast.Document) {}
func (_ visitingDataSourcePlanner) EnterInlineFragment(ref int)                       {}
func (_ visitingDataSourcePlanner) LeaveInlineFragment(ref int)                       {}
func (_ visitingDataSourcePlanner) EnterSelectionSet(ref int)                         {}
func (_ visitingDataSourcePlanner) LeaveSelectionSet(ref int)                         {}
func (_ visitingDataSourcePlanner) EnterField(ref int)                                {}
func (_ visitingDataSourcePlanner) EnterArgument(ref int)                             {}
func (_ visitingDataSourcePlanner) LeaveField(ref int)                                {}

func SimpleDataSourcePlanner(core CorePlanner) Planner {
	return &visitingDataSourcePlanner{
		CorePlanner: core,
	}
}

type Argument interface {
	ArgName() []byte
}

type ContextVariableArgument struct {
	Name         []byte
	VariableName []byte
}

func (c *ContextVariableArgument) ArgName() []byte {
	return c.Name
}

type PathSelector struct {
	Path string
}

type ObjectVariableArgument struct {
	Name         []byte
	PathSelector PathSelector
}

func (o *ObjectVariableArgument) ArgName() []byte {
	return o.Name
}

type StaticVariableArgument struct {
	Name  []byte
	Value []byte
}

func (s *StaticVariableArgument) ArgName() []byte {
	return s.Name
}

type ListArgument struct {
	Name      []byte
	Arguments []Argument
}

func (l ListArgument) ArgName() []byte {
	return l.Name
}

func isWhitelistedScheme(scheme string, whitelistedSchemes []string, defaultSchemes []string) bool {
	schemes := append(whitelistedSchemes, defaultSchemes...)
	for _, whitelistedScheme := range schemes {
		if scheme == whitelistedScheme {
			return true
		}
	}

	return false
}

func parseURLBytes(urlArg []byte) (parsedURL *url.URL, rawURL string, err error) {
	rawURL = string(urlArg)
	parsedURL, err = url.Parse(rawURL)
	return parsedURL, rawURL, err
}
