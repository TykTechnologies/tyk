package pathnormalizer

import (
	"github.com/TykTechnologies/tyk/internal/oasutil"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/internal/utils"
	"github.com/getkin/kin-openapi/openapi3"
)

// Mapper
// Primary responsibility is reverse mapping from "normalized" endpoints to "extended"
// Secondary responsibility is avoiding collisions of operation id and endpoint's collision too.
type Mapper struct {
	extended   *openapi3.Paths
	normalized *openapi3.Paths

	extendedMap   map[endpoint]*Entry
	normalizedMap map[endpoint]*Entry
	operationsMap map[string]*Entry
}

func NewMapper(in *openapi3.Paths) (*Mapper, error) {
	normalizedPaths := openapi3.NewPaths()
	in = reflect.Clone(in)
	entriesNumber := countPathsEntries(in)

	mapper := &Mapper{
		normalized:    normalizedPaths,
		extended:      in,
		extendedMap:   make(map[endpoint]*Entry, entriesNumber),
		normalizedMap: make(map[endpoint]*Entry, entriesNumber),
		operationsMap: make(map[string]*Entry, entriesNumber),
	}

	parser := NewParser()

	// todo: think of sorting
	for _, item := range oasutil.SortByPathLength(*in) {
		normalized, err := parser.Parse(item.Path)

		if err != nil {
			return nil, err
		}

		// process custom params from command line
		pathItem := reflect.Clone(item.PathItem)
		params := parameters{&pathItem.Parameters}

		for _, parameterRef := range normalized.ParameterRefs() {
			params.replaceOrAppend(parameterRef)
		}

		normalizedPaths.Set(normalized.path, pathItem)

		for method, pItem := range item.Operations() {
			if err = mapper.add(Entry{
				Method:      method,
				Extended:    item.Path,
				Normalized:  normalized.path,
				OperationID: pItem.OperationID,
			}); err != nil {
				return nil, err
			}
		}
	}

	return mapper, nil
}

func MustMapper(in *openapi3.Paths) *Mapper {
	mapper, err := NewMapper(in)

	if err != nil {
		panic(err)
	}

	return mapper
}

func (m *Mapper) add(newEntry Entry) error {
	if existent, ok := m.operationsMap[newEntry.OperationID]; ok {
		return newCollisionError(*existent, newEntry)
	}

	if existent, ok := m.extendedMap[newEntry.extendedEndpoint()]; ok {
		return newCollisionError(*existent, newEntry)
	}

	if existent, ok := m.normalizedMap[newEntry.normalizedEndpoint()]; ok {
		return newCollisionError(*existent, newEntry)
	}

	m.operationsMap[newEntry.OperationID] = &newEntry
	m.extendedMap[newEntry.extendedEndpoint()] = &newEntry
	m.normalizedMap[newEntry.normalizedEndpoint()] = &newEntry

	return nil
}

func (m *Mapper) GetParametersByNormalized(path, method string) openapi3.Parameters {
	entry, ok := m.normalizedMap[endpoint{Path: path, Method: method}]

	if !ok {
		return nil
	}

	pathItem := m.extended.Value(entry.Extended)
	if pathItem == nil {
		return nil
	}

	return reflect.Clone(pathItem.Parameters)
}

func (m *Mapper) FindOrCreateByNormalized(path, method string) (Entry, error) {
	// does classic api support patterns? if so this implementation could be wrong
	if entry, ok := m.normalizedMap[endpoint{Path: path, Method: method}]; ok {
		return *entry, nil
	}

	entry := Entry{
		Method:      method,
		OperationID: utils.OperationId(path, method),
		Extended:    path,
		Normalized:  path,
	}

	if err := m.add(entry); err != nil {
		return Entry{}, err
	}

	return entry, nil
}

func (m *Mapper) Normalized() *openapi3.Paths {
	return reflect.Clone(m.normalized)
}

type Entry struct {
	OperationID string
	Method      string

	// represents extended endpoint
	// e.g. /user/id:[0-9]+
	// as well as  /user/{id}
	Extended string

	// represents normalized endpoint path
	// is fully compatible with OAS path
	Normalized string
}

func (m Entry) extendedEndpoint() endpoint {
	return endpoint{
		Path:   m.Extended,
		Method: m.Method,
	}
}

func (m Entry) normalizedEndpoint() endpoint {
	return endpoint{
		Path:   m.Normalized,
		Method: m.Method,
	}
}

type endpoint struct {
	Path   string
	Method string
}

func countPathsEntries(in *openapi3.Paths) int {
	var res = 0

	for _, op := range in.Map() {
		res += len(op.Operations())
	}

	return res
}
