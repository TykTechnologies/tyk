package ast

import "github.com/jensneuse/graphql-go-tools/pkg/lexer/position"

type RootOperationTypeDefinitionList struct {
	LBrace position.Position // {
	Refs   []int             // RootOperationTypeDefinition
	RBrace position.Position // }
}

type RootOperationTypeDefinition struct {
	OperationType OperationType     // one of query, mutation, subscription
	Colon         position.Position // :
	NamedType     Type              // e.g. Query
}

func (d *Document) RootOperationTypeDefinitionNameString(ref int) string {
	return d.RootOperationTypeDefinitions[ref].OperationType.String()
}

func (d *Document) RootOperationTypeDefinitionIsFirstInSchemaDefinition(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindSchemaDefinition:
		if len(d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs) == 0 {
			return false
		}
		return ref == d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs[0]
	case NodeKindSchemaExtension:
		if len(d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs) == 0 {
			return false
		}
		return ref == d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs[0]
	default:
		return false
	}
}

func (d *Document) RootOperationTypeDefinitionIsLastInSchemaDefinition(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindSchemaDefinition:
		return d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs[len(d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs)-1] == ref
	case NodeKindSchemaExtension:
		return d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs[len(d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs)-1] == ref
	default:
		return false
	}
}

func (d *Document) CreateRootOperationTypeDefinition(operationType OperationType, rootNodeIndex int) (ref int) {
	switch operationType {
	case OperationTypeQuery:
		d.Index.QueryTypeName = []byte("Query")
	case OperationTypeMutation:
		d.Index.MutationTypeName = []byte("Mutation")
	case OperationTypeSubscription:
		d.Index.SubscriptionTypeName = []byte("Subscription")
	default:
		return
	}

	nameRef := d.ObjectTypeDefinitionNameRef(d.RootNodes[rootNodeIndex].Ref)
	return d.AddRootOperationTypeDefinition(RootOperationTypeDefinition{
		OperationType: operationType,
		NamedType: Type{
			TypeKind: TypeKindNamed,
			Name:     nameRef,
		},
	})
}

func (d *Document) AddRootOperationTypeDefinition(rootOperationTypeDefinition RootOperationTypeDefinition) (ref int) {
	d.RootOperationTypeDefinitions = append(d.RootOperationTypeDefinitions, rootOperationTypeDefinition)
	return len(d.RootOperationTypeDefinitions) - 1
}

func (d *Document) ImportRootOperationTypeDefinition(name string, operationType OperationType) (ref int) {
	operationTypeDefinition := RootOperationTypeDefinition{
		OperationType: operationType,
		NamedType: Type{
			Name: d.Input.AppendInputString(name),
		},
	}

	return d.AddRootOperationTypeDefinition(operationTypeDefinition)
}
