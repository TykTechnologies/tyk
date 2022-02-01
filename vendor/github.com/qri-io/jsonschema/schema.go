package jsonschema

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	jptr "github.com/qri-io/jsonpointer"
)

// Must turns a JSON string into a *Schema, panicing if parsing fails.
// Useful for declaring Schemas in Go code.
func Must(jsonString string) *Schema {
	s := &Schema{}
	if err := s.UnmarshalJSON([]byte(jsonString)); err != nil {
		panic(err)
	}
	return s
}

type schemaType int

const (
	schemaTypeObject schemaType = iota
	schemaTypeFalse
	schemaTypeTrue
)

// Schema is the top-level structure defining a json schema
type Schema struct {
	schemaType    schemaType
	docPath       string
	hasRegistered bool

	id string

	extraDefinitions map[string]json.RawMessage
	keywords         map[string]Keyword
	orderedkeywords  []string
}

// NewSchema allocates a new Schema Keyword/Validator
func NewSchema() Keyword {
	return &Schema{}
}

// HasKeyword is a utility function for checking if the given schema
// has an instance of the required keyword
func (s *Schema) HasKeyword(key string) bool {
	_, ok := s.keywords[key]
	return ok
}

// Register implements the Keyword interface for Schema
func (s *Schema) Register(uri string, registry *SchemaRegistry) {
	schemaDebug("[Schema] Register")
	if s.hasRegistered {
		return
	}
	s.hasRegistered = true
	registry.RegisterLocal(s)

	// load default keyset if no other is present
	if !IsRegistryLoaded() {
		LoadDraft2019_09()
	}

	address := s.id
	if uri != "" && address != "" {
		address, _ = SafeResolveURL(uri, address)
	}
	if s.docPath == "" && address != "" && address[0] != '#' {
		docURI := ""
		if u, err := url.Parse(address); err != nil {
			docURI, _ = SafeResolveURL("https://qri.io", address)
		} else {
			docURI = u.String()
		}
		s.docPath = docURI
		GetSchemaRegistry().Register(s)
		uri = docURI
	}

	for _, keyword := range s.keywords {
		keyword.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for Schema
func (s *Schema) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer.IsEmpty() {
		if s.docPath != "" {
			s.docPath, _ = SafeResolveURL(uri, s.docPath)
		} else {
			s.docPath = uri
		}
		return s
	}

	current := pointer.Head()

	if s.id != "" {
		if u, err := url.Parse(s.id); err == nil {
			if u.IsAbs() {
				uri = s.id
			} else {
				uri, _ = SafeResolveURL(uri, s.id)
			}
		}
	}

	keyword := s.keywords[*current]
	var keywordSchema *Schema
	if keyword != nil {
		keywordSchema = keyword.Resolve(pointer.Tail(), uri)
	}

	if keywordSchema != nil {
		return keywordSchema
	}

	found, err := pointer.Eval(s.extraDefinitions)
	if err != nil {
		return nil
	}
	if found == nil {
		return nil
	}

	if foundSchema, ok := found.(*Schema); ok {
		return foundSchema
	}

	return nil
}

// JSONProp implements the JSONPather for Schema
func (s Schema) JSONProp(name string) interface{} {
	if keyword, ok := s.keywords[name]; ok {
		return keyword
	}
	return s.extraDefinitions[name]
}

// JSONChildren implements the JSONContainer interface for Schema
func (s Schema) JSONChildren() map[string]JSONPather {
	ch := map[string]JSONPather{}

	if s.keywords != nil {
		for key, val := range s.keywords {
			if jp, ok := val.(JSONPather); ok {
				ch[key] = jp
			}
		}
	}

	return ch
}

// _schema is an internal struct for encoding & decoding purposes
type _schema struct {
	ID string `json:"$id,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for Schema
func (s *Schema) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			// boolean true Always passes validation, as if the empty schema {}
			*s = Schema{schemaType: schemaTypeTrue}
			return nil
		}
		// boolean false Always fails validation, as if the schema { "not":{} }
		*s = Schema{schemaType: schemaTypeFalse}
		return nil
	}

	if !IsRegistryLoaded() {
		LoadDraft2019_09()
	}

	_s := _schema{}
	if err := json.Unmarshal(data, &_s); err != nil {
		return err
	}

	sch := &Schema{
		id:       _s.ID,
		keywords: map[string]Keyword{},
	}

	valprops := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &valprops); err != nil {
		return err
	}

	for prop, rawmsg := range valprops {
		var keyword Keyword
		if IsRegisteredKeyword(prop) {
			keyword = GetKeyword(prop)
		} else if IsNotSupportedKeyword(prop) {
			schemaDebug(fmt.Sprintf("[Schema] WARN: '%s' is not supported and will be ignored\n", prop))
			continue
		} else {
			if sch.extraDefinitions == nil {
				sch.extraDefinitions = map[string]json.RawMessage{}
			}
			sch.extraDefinitions[prop] = rawmsg
			continue
		}
		if _, ok := keyword.(*Void); !ok {
			if err := json.Unmarshal(rawmsg, keyword); err != nil {
				return fmt.Errorf("error unmarshaling %s from json: %s", prop, err.Error())
			}
		}
		sch.keywords[prop] = keyword
	}

	// ensures proper and stable keyword validation order
	keyOrders := make([]_keyOrder, len(sch.keywords))
	i := 0
	for k := range sch.keywords {
		keyOrders[i] = _keyOrder{
			Key:   k,
			Order: GetKeywordOrder(k),
		}
		i++
	}
	sort.SliceStable(keyOrders, func(i, j int) bool {
		if keyOrders[i].Order == keyOrders[j].Order {
			return GetKeywordInsertOrder(keyOrders[i].Key) < GetKeywordInsertOrder(keyOrders[j].Key)
		}
		return keyOrders[i].Order < keyOrders[j].Order
	})
	orderedKeys := make([]string, len(sch.keywords))
	i = 0
	for _, keyOrder := range keyOrders {
		orderedKeys[i] = keyOrder.Key
		i++
	}
	sch.orderedkeywords = orderedKeys

	*s = Schema(*sch)
	return nil
}

// _keyOrder is an internal struct assigning evaluation order of keywords
type _keyOrder struct {
	Key   string
	Order int
}

// Validate initiates a fresh validation state and triggers the evaluation
func (s *Schema) Validate(ctx context.Context, data interface{}) *ValidationState {
	currentState := NewValidationState(s)
	s.ValidateKeyword(ctx, currentState, data)
	return currentState
}

// ValidateKeyword uses the schema to check an instance, collecting validation
// errors in a slice
func (s *Schema) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Schema] Validating")
	if s == nil {
		currentState.AddError(data, fmt.Sprintf("schema is nil"))
		return
	}
	if s.schemaType == schemaTypeTrue {
		return
	}
	if s.schemaType == schemaTypeFalse {
		currentState.AddError(data, fmt.Sprintf("schema is always false"))
		return
	}

	s.Register("", currentState.LocalRegistry)
	currentState.LocalRegistry.RegisterLocal(s)

	currentState.Local = s

	refKeyword := s.keywords["$ref"]

	if refKeyword == nil {
		if currentState.BaseURI == "" {
			currentState.BaseURI = s.docPath
		} else if s.docPath != "" {
			if u, err := url.Parse(s.docPath); err == nil {
				if u.IsAbs() {
					currentState.BaseURI = s.docPath
				} else {
					currentState.BaseURI, _ = SafeResolveURL(currentState.BaseURI, s.docPath)
				}
			}
		}
	}

	if currentState.BaseURI != "" && strings.HasSuffix(currentState.BaseURI, "#") {
		currentState.BaseURI = strings.TrimRight(currentState.BaseURI, "#")
	}

	// TODO(arqu): only on versions bellow draft2019_09
	// if refKeyword != nil {
	// 	refKeyword.ValidateKeyword(currentState, errs)
	// 	return
	// }

	s.validateSchemakeywords(ctx, currentState, data)
}

// validateSchemakeywords triggers validation of sub schemas and keywords
func (s *Schema) validateSchemakeywords(ctx context.Context, currentState *ValidationState, data interface{}) {
	if s.keywords != nil {
		for _, keyword := range s.orderedkeywords {
			s.keywords[keyword].ValidateKeyword(ctx, currentState, data)
		}
	}
}

// ValidateBytes performs schema validation against a slice of json
// byte data
func (s *Schema) ValidateBytes(ctx context.Context, data []byte) ([]KeyError, error) {
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("error parsing JSON bytes: %w", err)
	}
	vs := s.Validate(ctx, doc)
	return *vs.Errs, nil
}

// TopLevelType returns a string representing the schema's top-level type.
func (s *Schema) TopLevelType() string {
	if t, ok := s.keywords["type"].(*Type); ok {
		return t.String()
	}
	return "unknown"
}

// MarshalJSON implements the json.Marshaler interface for Schema
func (s Schema) MarshalJSON() ([]byte, error) {
	switch s.schemaType {
	case schemaTypeFalse:
		return []byte("false"), nil
	case schemaTypeTrue:
		return []byte("true"), nil
	default:
		obj := map[string]interface{}{}

		for k, v := range s.keywords {
			obj[k] = v
		}
		for k, v := range s.extraDefinitions {
			obj[k] = v
		}
		return json.Marshal(obj)
	}
}
