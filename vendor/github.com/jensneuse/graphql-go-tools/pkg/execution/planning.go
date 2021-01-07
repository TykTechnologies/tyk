package execution

import (
	"bytes"
	"io"
	"os"

	"github.com/jensneuse/pipeline/pkg/pipe"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type Planner struct {
	walker  *astvisitor.Walker
	visitor *planningVisitor
}

type DataSourceDefinition struct {
	// the type name to which the data source is attached
	TypeName []byte
	// the field on the type to which the data source is attached
	FieldName []byte
	// a factory method to return a new planner
	DataSourcePlannerFactory func() datasource.Planner
}

func NewPlanner(base *datasource.BasePlanner) *Planner {
	walker := astvisitor.NewWalker(48)
	visitor := planningVisitor{
		Walker: &walker,
		base:   base,
	}

	walker.RegisterDocumentVisitor(&visitor)
	walker.RegisterEnterFieldVisitor(&visitor)
	walker.RegisterEnterArgumentVisitor(&visitor)
	walker.RegisterLeaveFieldVisitor(&visitor)
	walker.RegisterEnterSelectionSetVisitor(&visitor)
	walker.RegisterLeaveSelectionSetVisitor(&visitor)
	walker.RegisterEnterInlineFragmentVisitor(&visitor)
	walker.RegisterLeaveInlineFragmentVisitor(&visitor)
	walker.RegisterEnterOperationVisitor(&visitor)

	return &Planner{
		walker:  &walker,
		visitor: &visitor,
	}
}

func (p *Planner) Plan(operation, definition *ast.Document, operationName string, report *operationreport.Report) RootNode {
	p.visitor.operationName = operationName
	p.walker.Walk(operation, definition, report)
	return p.visitor.rootNode
}

type planningVisitor struct {
	*astvisitor.Walker
	base                  *datasource.BasePlanner
	operation, definition *ast.Document
	rootNode              RootNode
	currentNode           []Node
	planners              []dataSourcePlannerRef
	operationName         string
	foundOperation        bool
	isSingleOperation     bool
}

type dataSourcePlannerRef struct {
	path     ast.Path
	fieldRef int
	planner  datasource.Planner
}

func (p *planningVisitor) EnterDocument(operation, definition *ast.Document) {
	p.operation, p.definition, p.base.Definition = operation, definition, definition
	p.foundOperation = false
	p.isSingleOperation = p.countOperationDefinitionsInRootNodes() == 1

	if len(operation.OperationDefinitions) == 0 {
		p.Walker.StopWithExternalErr(operationreport.ErrDocumentDoesntContainExecutableOperation())
		return
	}

	p.currentNode = p.currentNode[:0]
	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.EnterDocument(operation, definition)
	}
}

func (p *planningVisitor) LeaveDocument(operation, definition *ast.Document) {
	if !p.isSingleOperation && len(p.operationName) == 0 {
		p.Report.AddExternalError(operationreport.ErrRequiredOperationNameIsMissing())
	} else if !p.foundOperation {
		p.Report.AddExternalError(operationreport.ErrOperationWithProvidedOperationNameNotFound(p.operationName))
	}
}

func (p *planningVisitor) EnterOperationDefinition(ref int) {
	operationName := p.operation.OperationDefinitionNameString(ref)
	if !p.isSingleOperation && operationName != p.operationName {
		p.SkipNode()
		return
	}

	p.foundOperation = true
	obj := &Object{}
	p.rootNode = &Object{
		operationType: p.operation.OperationDefinitions[ref].OperationType,
		Fields: []Field{
			{
				Name:  literal.DATA,
				Value: obj,
			},
		},
	}
	p.currentNode = append(p.currentNode, obj)
}

func (p *planningVisitor) EnterInlineFragment(ref int) {
	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.EnterInlineFragment(ref)
	}
}

func (p *planningVisitor) LeaveInlineFragment(ref int) {
	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.LeaveInlineFragment(ref)
	}
}

func (p *planningVisitor) EnterField(ref int) {

	definition, exists := p.FieldDefinition(ref)
	if !exists {
		return
	}

	typeName := p.definition.NodeResolverTypeNameString(p.EnclosingTypeDefinition, p.Path)
	fieldName := p.operation.FieldNameString(ref)

	plannerFactory := p.base.Config.DataSourcePlannerFactoryForTypeField(typeName, fieldName)
	if plannerFactory != nil {
		planner := plannerFactory.DataSourcePlanner()
		planner.Configure(p.operation, p.definition, p.Walker)
		p.planners = append(p.planners, dataSourcePlannerRef{
			path:     p.Path,
			fieldRef: ref,
			planner:  planner,
		})
	}

	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.EnterField(ref)
	}

	switch parent := p.currentNode[len(p.currentNode)-1].(type) {
	case *Object:

		var skipCondition BooleanCondition
		ancestor := p.Ancestors[len(p.Ancestors)-2]
		if ancestor.Kind == ast.NodeKindInlineFragment {
			typeConditionName := p.operation.InlineFragmentTypeConditionName(ancestor.Ref)
			skipCondition = &IfNotEqual{
				Left: &datasource.ObjectVariableArgument{
					PathSelector: datasource.PathSelector{
						Path: "__typename",
					},
				},
				Right: &datasource.StaticVariableArgument{
					Value: typeConditionName,
				},
			}
		}

		dataResolvingConfig := p.fieldDataResolvingConfig(ref)

		var value Node
		fieldDefinitionType := p.definition.FieldDefinitionType(definition)
		if p.definition.TypeIsList(fieldDefinitionType) {

			if !p.operation.FieldHasSelections(ref) {
				value = &Value{
					ValueType: p.jsonValueType(fieldDefinitionType),
				}
			} else {
				value = &Object{}
			}

			list := &List{
				DataResolvingConfig: dataResolvingConfig,
				Value:               value,
			}

			firstNValue, ok := p.FieldDefinitionDirectiveArgumentValueByName(ref, []byte("ListFilterFirstN"), []byte("n"))
			if ok {
				if firstNValue.Kind == ast.ValueKindInteger {
					firstN := p.definition.IntValueAsInt(firstNValue.Ref)
					list.Filter = &ListFilterFirstN{
						FirstN: int(firstN),
					}
				}
			}

			parent.Fields = append(parent.Fields, Field{
				Name:  p.operation.FieldNameBytes(ref),
				Value: list,
				Skip:  skipCondition,
			})

			p.currentNode = append(p.currentNode, value)
			return
		}

		if !p.operation.FieldHasSelections(ref) {
			value = &Value{
				DataResolvingConfig: dataResolvingConfig,
				ValueType:           p.jsonValueType(fieldDefinitionType),
			}
		} else {
			value = &Object{
				DataResolvingConfig: dataResolvingConfig,
			}
		}

		parent.Fields = append(parent.Fields, Field{
			Name:  p.operation.FieldAliasOrNameBytes(ref),
			Value: value,
			Skip:  skipCondition,
		})

		p.currentNode = append(p.currentNode, value)
	}
}

func (p *planningVisitor) EnterArgument(ref int) {
	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.EnterArgument(ref)
	}
}

func (p *planningVisitor) LeaveField(ref int) {

	var plannedDataSource datasource.DataSource
	var plannedArgs []datasource.Argument

	if len(p.planners) != 0 {

		p.planners[len(p.planners)-1].planner.LeaveField(ref)

		if p.planners[len(p.planners)-1].path.Equals(p.Path) && p.planners[len(p.planners)-1].fieldRef == ref {
			plannedDataSource, plannedArgs = p.planners[len(p.planners)-1].planner.Plan(p.fieldContextVariableArguments(ref))
			p.planners = p.planners[:len(p.planners)-1]

			if len(p.currentNode) >= 2 {
				switch parent := p.currentNode[len(p.currentNode)-2].(type) {
				case *Object:
					for i := 0; i < len(parent.Fields); i++ {
						if bytes.Equal(p.operation.FieldAliasOrNameBytes(ref), parent.Fields[i].Name) {

							pathName := p.operation.FieldAliasOrNameString(ref)
							parent.Fields[i].HasResolvedData = true

							singleFetch := &SingleFetch{
								Source: &DataSourceInvocation{
									Args:       plannedArgs,
									DataSource: plannedDataSource,
								},
								BufferName: pathName,
							}

							if parent.Fetch == nil {
								parent.Fetch = singleFetch
							} else {
								switch fetch := parent.Fetch.(type) {
								case *ParallelFetch:
									fetch.Fetches = append(fetch.Fetches, singleFetch)
								case *SerialFetch:
									fetch.Fetches = append(fetch.Fetches, singleFetch)
								case *SingleFetch:
									first := *fetch
									parent.Fetch = &ParallelFetch{
										Fetches: []Fetch{
											&first,
											singleFetch,
										},
									}
								}
							}
						}
					}
				}
			}
		}
	}

	p.currentNode = p.currentNode[:len(p.currentNode)-1]
}

func (p *planningVisitor) fieldContextVariableArguments(ref int) []datasource.Argument {
	// args
	if p.operation.FieldHasArguments(ref) {
		refs := p.operation.FieldArguments(ref)
		out := make([]datasource.Argument, len(refs))
		for j, i := range refs {
			argName := p.operation.ArgumentNameBytes(i)
			value := p.operation.ArgumentValue(i)
			if value.Kind != ast.ValueKindVariable {
				continue
			}
			variableName := p.operation.VariableValueNameBytes(value.Ref)
			name := append([]byte(".arguments."), argName...)
			arg := &datasource.ContextVariableArgument{
				VariableName: variableName,
				Name:         make([]byte, len(name)),
			}
			copy(arg.Name, name)
			out[j] = arg
		}
		return out
	}
	return nil
}

func (p *planningVisitor) EnterSelectionSet(ref int) {
	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.EnterSelectionSet(ref)
	}
}

func (p *planningVisitor) LeaveSelectionSet(ref int) {
	if len(p.planners) != 0 {
		p.planners[len(p.planners)-1].planner.LeaveSelectionSet(ref)
	}
}

func (p *planningVisitor) jsonValueType(valueType int) JSONValueType {
	typeName := p.definition.ResolveTypeNameBytes(valueType)
	switch {
	case bytes.Equal(typeName, literal.INT):
		return IntegerValueType
	case bytes.Equal(typeName, literal.BOOLEAN):
		return BooleanValueType
	case bytes.Equal(typeName, literal.FLOAT):
		return FloatValueType
	default:
		return StringValueType
	}
}

func (p *planningVisitor) fieldDataResolvingConfig(ref int) DataResolvingConfig {
	return DataResolvingConfig{
		PathSelector:   p.fieldPathSelector(ref),
		Transformation: p.fieldTransformation(ref),
	}
}

func (p *planningVisitor) fieldPathSelector(ref int) (selector datasource.PathSelector) {
	fieldName := p.operation.FieldNameString(ref)
	typeName := p.definition.NodeResolverTypeNameString(p.EnclosingTypeDefinition, p.Path)
	mapping := p.base.Config.MappingForTypeField(typeName, fieldName)
	if mapping == nil {
		selector.Path = fieldName
		return
	}
	if mapping.Disabled {
		return
	}
	selector.Path = mapping.Path
	return
}

func (p *planningVisitor) fieldTransformation(ref int) Transformation {
	definition, ok := p.FieldDefinition(ref)
	if !ok {
		return nil
	}
	transformationDirective, ok := p.definition.FieldDefinitionDirectiveByName(definition, literal.TRANSFORMATION)
	if !ok {
		return nil
	}
	modeValue, ok := p.definition.DirectiveArgumentValueByName(transformationDirective, literal.MODE)
	if !ok || modeValue.Kind != ast.ValueKindEnum {
		return nil
	}
	mode := unsafebytes.BytesToString(p.definition.EnumValueNameBytes(modeValue.Ref))
	switch mode {
	case "PIPELINE":
		return p.pipelineTransformation(transformationDirective)
	default:
		return nil
	}
}

func (p *planningVisitor) pipelineTransformation(directive int) *PipelineTransformation {
	var configReader io.Reader
	configFileStringValue, ok := p.definition.DirectiveArgumentValueByName(directive, literal.PIPELINE_CONFIG_FILE)
	if ok && configFileStringValue.Kind == ast.ValueKindString {
		reader, err := os.Open(p.definition.StringValueContentString(configFileStringValue.Ref))
		if err != nil {
			return nil
		}
		defer reader.Close()
		configReader = reader
	}
	configStringValue, ok := p.definition.DirectiveArgumentValueByName(directive, literal.PIPELINE_CONFIG_STRING)
	if ok && configStringValue.Kind == ast.ValueKindString {
		configReader = bytes.NewReader(p.definition.StringValueContentBytes(configStringValue.Ref))
	}
	if configReader == nil {
		return nil
	}
	var pipeline pipe.Pipeline
	err := pipeline.FromConfig(configReader)
	if err != nil {
		return nil
	}
	return &PipelineTransformation{
		pipeline: pipeline,
	}
}

func (p *planningVisitor) countOperationDefinitionsInRootNodes() (count int) {
	for i := range p.operation.RootNodes {
		if p.operation.RootNodes[i].Kind == ast.NodeKindOperationDefinition {
			count++
		}
	}

	return count
}
