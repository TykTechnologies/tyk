package operationreport

import (
	"fmt"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
)

type ExternalError struct {
	Message   string     `json:"message"`
	Path      ast.Path   `json:"path"`
	Locations []Location `json:"locations"`
}

type Location struct {
	Line   uint32 `json:"line"`
	Column uint32 `json:"column"`
}

func ErrFieldUndefinedOnType(fieldName, typeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("field: %s not defined on type: %s", fieldName, typeName)
	return err
}

func ErrTypeUndefined(typeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("type not defined: %s", typeName)
	return err
}

func ErrOperationNameMustBeUnique(operationName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("operation name must be unique: %s", operationName)
	return err
}

func ErrAnonymousOperationMustBeTheOnlyOperationInDocument() (err ExternalError) {
	err.Message = fmt.Sprintf("anonymous operation name the only operation in a graphql document")
	return err
}

func ErrSubscriptionMustOnlyHaveOneRootSelection(subscriptionName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("subscription: %s must only have one root selection", subscriptionName)
	return err
}

func ErrFieldSelectionOnUnion(fieldName, unionName ast.ByteSlice) (err ExternalError) {

	err.Message = fmt.Sprintf("cannot select field: %s on union: %s", fieldName, unionName)
	return err
}

func ErrFieldsConflict(objectName, leftType, rightType ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("fields '%s' conflict because they return conflicting types '%s' and '%s'", objectName, leftType, rightType)
	return err
}

func ErrTypesForFieldMismatch(objectName, leftType, rightType ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("differing types '%s' and '%s' for objectName '%s'", leftType, rightType, objectName)
	return err
}

func ErrResponseOfDifferingTypesMustBeOfSameShape(leftObjectName, rightObjectName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("objects '%s' and '%s' on differing response types must be of same response shape", leftObjectName, rightObjectName)
	return err
}

func ErrDifferingFieldsOnPotentiallySameType(objectName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("differing fields for objectName '%s' on (potentially) same type", objectName)
	return err
}

func ErrFieldSelectionOnScalar(fieldName, scalarTypeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("cannot select field: %s on scalar %s", fieldName, scalarTypeName)
	return err
}

func ErrMissingFieldSelectionOnNonScalar(fieldName, enclosingTypeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("non scalar field: %s on type: %s must have selections", fieldName, enclosingTypeName)
	return err
}

func ErrArgumentNotDefinedOnNode(argName, node ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("argument: %s not defined on node: %s", argName, node)
	return err
}

func ErrValueDoesntSatisfyInputValueDefinition(value, inputType ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("value: %s doesn't satisfy inputType: %s", value, inputType)
	return err
}

func ErrVariableNotDefinedOnOperation(variableName, operationName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("variable: %s not defined on operation: %s", variableName, operationName)
	return err
}

func ErrVariableDefinedButNeverUsed(variableName, operationName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("variable: %s defined on operation: %s but never used", variableName, operationName)
	return err
}

func ErrVariableMustBeUnique(variableName, operationName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("variable: %s must be unique per operation: %s", variableName, operationName)
	return err
}

func ErrVariableNotDefinedOnArgument(variableName, argumentName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("variable: %s not defined on argument: %s", variableName, argumentName)
	return err
}

func ErrVariableOfTypeIsNoValidInputValue(variableName, ofTypeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("variable: %s of type: %s is no valid input value type", variableName, ofTypeName)
	return err
}

func ErrArgumentMustBeUnique(argName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("argument: %s must be unique", argName)
	return err
}

func ErrArgumentRequiredOnField(argName, fieldName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("argument: %s is required on field: %s but missing", argName, fieldName)
	return err
}

func ErrArgumentOnFieldMustNotBeNull(argName, fieldName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("argument: %s on field: %s must not be null", argName, fieldName)
	return err
}

func ErrFragmentSpreadFormsCycle(spreadName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("fragment spread: %s forms fragment cycle", spreadName)
	return err
}

func ErrFragmentDefinedButNotUsed(fragmentName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("fragment: %s defined but not used", fragmentName)
	return err
}

func ErrFragmentUndefined(fragmentName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("fragment: %s undefined", fragmentName)
	return err
}

func ErrInlineFragmentOnTypeDisallowed(onTypeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("inline fragment on type: %s disallowed", onTypeName)
	return err
}

func ErrInlineFragmentOnTypeMismatchEnclosingType(fragmentTypeName, enclosingTypeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("inline fragment on type: %s mismatches enclosing type: %s", fragmentTypeName, enclosingTypeName)
	return err
}

func ErrFragmentDefinitionOnTypeDisallowed(fragmentName, onTypeName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("fragment: %s on type: %s disallowed", fragmentName, onTypeName)
	return err
}

func ErrFragmentDefinitionMustBeUnique(fragmentName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("fragment: %s must be unique per document", fragmentName)
	return err
}

func ErrDirectiveUndefined(directiveName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("directive: %s undefined", directiveName)
	return err
}

func ErrDirectiveNotAllowedOnNode(directiveName, nodeKindName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("directive: %s not allowed on node of kind: %s", directiveName, nodeKindName)
	return err
}

func ErrDirectiveMustBeUniquePerLocation(directiveName ast.ByteSlice) (err ExternalError) {
	err.Message = fmt.Sprintf("directive: %s must be unique per location", directiveName)
	return err
}
