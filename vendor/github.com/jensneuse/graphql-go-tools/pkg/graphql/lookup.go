package graphql

import (
	"fmt"
)

type TypeFieldLookupKey string

func CreateTypeFieldLookupKey(typeName string, fieldName string) TypeFieldLookupKey {
	return TypeFieldLookupKey(fmt.Sprintf("%s.%s", typeName, fieldName))
}

func CreateTypeFieldArgumentsLookupMap(typeFieldArgs []TypeFieldArguments) map[TypeFieldLookupKey]TypeFieldArguments {
	if len(typeFieldArgs) == 0 {
		return nil
	}

	lookupMap := make(map[TypeFieldLookupKey]TypeFieldArguments)
	for _, currentTypeFieldArgs := range typeFieldArgs {
		lookupMap[CreateTypeFieldLookupKey(currentTypeFieldArgs.TypeName, currentTypeFieldArgs.FieldName)] = currentTypeFieldArgs
	}

	return lookupMap
}
