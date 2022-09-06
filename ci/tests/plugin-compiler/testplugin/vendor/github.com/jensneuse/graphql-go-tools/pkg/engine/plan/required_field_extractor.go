package plan

import (
	"strings"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
)

var (
	fieldsArgumentNameBytes = []byte("fields")
)

// RequiredFieldExtractor extracts all required fields from an ast.Document
// containing a parsed federation subgraph SDL
// by visiting the directives specified in the federation specification
// and extracting the required meta data
type RequiredFieldExtractor struct {
	document *ast.Document
}

func NewRequiredFieldExtractor(document *ast.Document) *RequiredFieldExtractor {
	return &RequiredFieldExtractor{
		document: document,
	}
}

func (f *RequiredFieldExtractor) GetAllRequiredFields() FieldConfigurations {
	var fieldRequires FieldConfigurations

	f.addFieldsForObjectExtensionDefinitions(&fieldRequires)
	f.addFieldsForObjectDefinitions(&fieldRequires)

	return fieldRequires
}

func (f *RequiredFieldExtractor) addFieldsForObjectExtensionDefinitions(fieldRequires *FieldConfigurations) {
	for _, objectTypeExt := range f.document.ObjectTypeExtensions {
		objectType := objectTypeExt.ObjectTypeDefinition
		typeName := f.document.Input.ByteSliceString(objectType.Name)

		primaryKeys, exists := f.primaryKeyFieldsIfObjectTypeIsEntity(objectType)
		if !exists {
			continue
		}

		for _, fieldDefinitionRef := range objectType.FieldsDefinition.Refs {
			if f.document.FieldDefinitionHasNamedDirective(fieldDefinitionRef,federationExternalDirectiveName) {
				continue
			}

			fieldName := f.document.FieldDefinitionNameString(fieldDefinitionRef)

			requiredFields := make([]string, len(primaryKeys))
			copy(requiredFields, primaryKeys)

			requiredFieldsByRequiresDirective := f.requiredFieldsByRequiresDirective(fieldDefinitionRef)
			requiredFields = append(requiredFields, requiredFieldsByRequiresDirective...)

			*fieldRequires = append(*fieldRequires, FieldConfiguration{
				TypeName:       typeName,
				FieldName:      fieldName,
				RequiresFields: requiredFields,
			})
		}
	}
}

func (f *RequiredFieldExtractor) addFieldsForObjectDefinitions(fieldRequires *FieldConfigurations) {
	for _, objectType := range f.document.ObjectTypeDefinitions {
		typeName := f.document.Input.ByteSliceString(objectType.Name)

		primaryKeys, exists := f.primaryKeyFieldsIfObjectTypeIsEntity(objectType)
		if !exists {
			continue
		}

		primaryKeysSet := make(map[string]struct{}, len(primaryKeys))
		for _, val := range primaryKeys {
			primaryKeysSet[val] = struct{}{}
		}

		for _, fieldRef := range objectType.FieldsDefinition.Refs {
			fieldName := f.document.FieldDefinitionNameString(fieldRef)
			if _, exists := primaryKeysSet[fieldName]; exists { // Field is part of primary key, it couldn't have any required fields
				continue
			}

			requiredFields := make([]string, len(primaryKeys))
			copy(requiredFields, primaryKeys)

			*fieldRequires = append(*fieldRequires, FieldConfiguration{
				TypeName:       typeName,
				FieldName:      fieldName,
				RequiresFields: requiredFields,
			})
		}
	}
}

func (f *RequiredFieldExtractor) requiredFieldsByRequiresDirective(fieldDefinitionRef int) []string {
	for _, directiveRef := range f.document.FieldDefinitions[fieldDefinitionRef].Directives.Refs {
		if directiveName := f.document.DirectiveNameString(directiveRef); directiveName != federationRequireDirectiveName {
			continue
		}

		value, exists := f.document.DirectiveArgumentValueByName(directiveRef, fieldsArgumentNameBytes)
		if !exists {
			continue
		}
		if value.Kind != ast.ValueKindString {
			continue
		}

		fieldsStr := f.document.StringValueContentString(value.Ref)

		return strings.Split(fieldsStr, " ")
	}

	return nil
}

func (f *RequiredFieldExtractor) primaryKeyFieldsIfObjectTypeIsEntity(objectType ast.ObjectTypeDefinition) (keyFields []string, ok bool) {
	for _, directiveRef := range objectType.Directives.Refs {
		if directiveName := f.document.DirectiveNameString(directiveRef); directiveName != federationKeyDirectiveName {
			continue
		}

		value, exists := f.document.DirectiveArgumentValueByName(directiveRef, fieldsArgumentNameBytes)
		if !exists {
			continue
		}
		if value.Kind != ast.ValueKindString {
			continue
		}

		fieldsStr := f.document.StringValueContentString(value.Ref)

		return strings.Split(fieldsStr, " "), true
	}

	return nil, false
}
