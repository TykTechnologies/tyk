package pathnormalizer

import (
	"github.com/TykTechnologies/tyk/internal/oasutil"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/internal/utils"
	"github.com/getkin/kin-openapi/openapi3"
	"regexp"
)

// Mapper
// Primary responsibility is reverse mapping from "normalized" endpoints to "extended"
// Secondary responsibility is avoiding collisions of operation id and endpoint's collision too.
type Mapper struct {
	parser *Parser

	extended   *openapi3.Paths
	normalized *openapi3.Paths

	extendedMap   map[endpoint]*Entry
	normalizedMap map[endpoint]*Entry
	operationsMap map[string]*Entry
}

func NewMapper(in *openapi3.Paths) (*Mapper, error) {
	m, err := newMapper(in)

	if err != nil {
		log.WithError(err).Error("failed to create mapper")
	}

	return m, err
}

func newMapper(in *openapi3.Paths) (*Mapper, error) {
	in = reflect.Clone(in)
	normalizedPaths := openapi3.NewPaths()
	entriesNumber := countPathsEntries(in)

	mapper := &Mapper{
		parser:        NewParser(),
		normalized:    normalizedPaths,
		extended:      in,
		extendedMap:   make(map[endpoint]*Entry, entriesNumber),
		normalizedMap: make(map[endpoint]*Entry, entriesNumber),
		operationsMap: make(map[string]*Entry, entriesNumber),
	}

	for _, item := range oasutil.SortByPathLength(*in) {
		normalized, err := mapper.parser.Parse(item.Path)

		if err != nil {
			return nil, err
		}

		// process custom params from command line
		pathItem := reflect.Clone(item.PathItem)
		extractParametersFromPath(&pathItem.Parameters, normalized.ParameterRefs())
		normalizedPaths.Set(normalized.path, pathItem)

		for method, op := range item.Operations() {
			extractParametersFromPath(&op.Parameters, normalized.ParameterRefs())

			if err = mapper.add(Entry{
				Method:      method,
				Extended:    item.Path,
				Normalized:  normalized.path,
				OperationID: defaultIdIfNotDefined(op.OperationID, item.Path, method),
				parameters:  &pathItem.Parameters,
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

func MustDummyMapper() *Mapper {
	return MustMapper(openapi3.NewPaths())
}

func (m *Mapper) add(newEntry Entry) error {
	newEntry.mapper = m

	if existent, ok := m.operationsMap[newEntry.OperationID]; ok {
		return newCollisionError(*existent, newEntry, collisionAtOperationId)
	}

	if existent, ok := m.extendedMap[newEntry.extendedEndpoint()]; ok {
		return newCollisionError(*existent, newEntry, collisionAtNormalized)
	}

	if existent, ok := m.normalizedMap[newEntry.normalizedEndpoint()]; ok {
		return newCollisionError(*existent, newEntry, collisionAtExtended)
	}

	m.operationsMap[newEntry.OperationID] = &newEntry
	m.extendedMap[newEntry.extendedEndpoint()] = &newEntry
	m.normalizedMap[newEntry.normalizedEndpoint()] = &newEntry

	return nil
}

func (m *Mapper) FindOrCreate(path, method string) (Entry, error) {
	entry, err := m.findOrCreate(path, method)

	if err != nil {
		log.WithError(err).Error("failed to find or create entry")
	}

	return entry, err
}

func (m *Mapper) findOrCreate(path, method string) (Entry, error) {
	ep := endpoint{Path: path, Method: method}

	// does classic api support patterns? if so this implementation could be wrong
	if entry, ok := m.normalizedMap[ep]; ok {
		return *entry, nil
	}

	if entry, ok := m.extendedMap[ep]; ok {
		return *entry, nil
	}

	normalized, err := m.parser.Parse(path)

	if err != nil {
		return Entry{}, err
	}

	pathItem := openapi3.PathItem{}
	pathItem.Parameters = openapi3.NewParameters()
	extractParametersFromPath(&pathItem.Parameters, normalized.ParameterRefs())

	entry := Entry{
		Method:      method,
		OperationID: utils.OperationId(path, method),
		Extended:    path,
		Normalized:  normalized.path,
		mapper:      m,
		parameters:  &pathItem.Parameters,
	}

	if err := m.add(entry); err != nil {
		return Entry{}, err
	}

	return entry, nil
}

func (m *Mapper) getNormalized() *openapi3.Paths {
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

	// path parameters
	parameters *openapi3.Parameters
	mapper     *Mapper
}

func (e Entry) ExtendPathParameters(dest *openapi3.Parameters) {
	wrapParameters(dest).extendBy(e.pathParameters())
}

func (e Entry) pathParameters() openapi3.Parameters {
	if e.mapper == nil {
		return nil
	}

	entry, ok := e.mapper.normalizedMap[e.normalizedEndpoint()]

	if !ok || entry.parameters == nil {
		return nil
	}

	return *entry.parameters
}

func (e Entry) extendedEndpoint() endpoint {
	return endpoint{
		Path:   e.Extended,
		Method: e.Method,
	}
}

func (e Entry) normalizedEndpoint() endpoint {
	return endpoint{
		Path:   e.Normalized,
		Method: e.Method,
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

func extractParametersFromPath(in *openapi3.Parameters, src openapi3.Parameters) {
	wrapParameters(in).extendBy(src)
}

func defaultIdIfNotDefined(opId string, path, method string) string {
	if emptyStringRe.MatchString(opId) {
		return utils.OperationId(path, method)
	}

	return opId
}

var emptyStringRe = regexp.MustCompile(`^\s*$`)
