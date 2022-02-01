package introspection_datasource

import (
	"context"
	"encoding/json"
	"io"

	"github.com/jensneuse/graphql-go-tools/pkg/introspection"
)

var (
	null = []byte("null")
)

type Source struct {
	introspectionData *introspection.Data
}

func (s *Source) Load(ctx context.Context, input []byte, w io.Writer) (err error) {
	var req introspectionInput
	if err := json.Unmarshal(input, &req); err != nil {
		return err
	}

	switch req.RequestType {
	case TypeRequestType:
		return s.singleType(w, req.TypeName)
	case TypeEnumValuesRequestType:
		return s.enumValuesForType(w, req.OnTypeName, req.IncludeDeprecated)
	case TypeFieldsRequestType:
		return s.fieldsForType(w, req.OnTypeName, req.IncludeDeprecated)
	}

	return json.NewEncoder(w).Encode(s.introspectionData.Schema)
}

func (s *Source) typeInfo(typeName *string) *introspection.FullType {
	if typeName == nil {
		return nil
	}

	for _, fullType := range s.introspectionData.Schema.Types {
		if fullType.Name == *typeName {
			return &fullType
		}
	}
	return nil
}

func (s *Source) writeNull(w io.Writer) error {
	_, err := w.Write(null)
	return err
}

func (s *Source) singleType(w io.Writer, typeName *string) error {
	typeInfo := s.typeInfo(typeName)
	if typeInfo == nil {
		return s.writeNull(w)
	}

	return json.NewEncoder(w).Encode(typeInfo)
}

func (s *Source) fieldsForType(w io.Writer, typeName *string, includeDeprecated bool) error {
	typeInfo := s.typeInfo(typeName)
	if typeInfo == nil {
		return s.writeNull(w)
	}

	if includeDeprecated {
		return json.NewEncoder(w).Encode(typeInfo.Fields)
	}

	fields := make([]introspection.Field, 0, len(typeInfo.Fields))
	for _, field := range typeInfo.Fields {
		if !field.IsDeprecated {
			fields = append(fields, field)
		}
	}

	return json.NewEncoder(w).Encode(fields)
}

func (s *Source) enumValuesForType(w io.Writer, typeName *string, includeDeprecated bool) error {
	typeInfo := s.typeInfo(typeName)
	if typeInfo == nil {
		return s.writeNull(w)
	}

	if includeDeprecated {
		return json.NewEncoder(w).Encode(typeInfo.EnumValues)
	}

	enumValues := make([]introspection.EnumValue, 0, len(typeInfo.EnumValues))
	for _, enumValue := range typeInfo.EnumValues {
		if !enumValue.IsDeprecated {
			enumValues = append(enumValues, enumValue)
		}
	}

	return json.NewEncoder(w).Encode(enumValues)
}
