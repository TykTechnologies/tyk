package pathnormalizer

import (
	"regexp"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/internal/oasutil"
	"github.com/TykTechnologies/tyk/internal/reflect"
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

	// parsedPaths caches normalization per path, and pathParams the parameters
	// derived from it. Both are keyed by path alone, never by endpoint: see parse.
	parsedPaths map[string]*NormalizedPath
	pathParams  map[string]*openapi3.Parameters
}

func NewMapper(in *openapi3.Paths) (*Mapper, error) {
	return newMapper(in)
}

func newMapper(in *openapi3.Paths) (*Mapper, error) {
	if in == nil {
		in = openapi3.NewPaths()
	}

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
		parsedPaths:   make(map[string]*NormalizedPath, entriesNumber),
		pathParams:    make(map[string]*openapi3.Parameters, entriesNumber),
	}

	for _, item := range oasutil.SortByPathLength(*in) {
		normalized, err := mapper.parse(item.Path)

		if err != nil {
			return nil, err
		}

		// process custom params from command line
		pathItem := reflect.Clone(item.PathItem)
		extractParametersFromPath(&pathItem.Parameters, normalized.ParameterRefs())
		normalizedPaths.Set(normalized.path, pathItem)
		mapper.pathParams[normalized.path] = &pathItem.Parameters

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

// FindOrCreate resolves an endpoint to its normalized path, creating the entry
// when the mapper has not seen it yet. The error is returned rather than logged:
// the caller knows which API and which endpoint it is converting, and is the one
// able to tell whoever asked for the conversion.
func (m *Mapper) FindOrCreate(path, method string) (Entry, error) {
	return m.findOrCreate(path, method)
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

	// An entry seeded from a document holds the OAS path key in Extended, so a
	// classic path never matches it by path alone. The operation ID does carry
	// the original classic path, which is how a document previously generated
	// from this very API is recognised on a later fill. Without this the second
	// fill mints a fresh placeholder and add() rejects it as an operation ID
	// collision.
	if entry, ok := m.operationsMap[operationId(path, method)]; ok {
		return *entry, nil
	}

	normalized, err := m.parse(path)

	if err != nil {
		return Entry{}, err
	}

	entry := Entry{
		Method:      method,
		OperationID: operationId(path, method),
		Extended:    path,
		Normalized:  normalized.path,
		mapper:      m,
		parameters:  m.parametersFor(normalized),
	}

	if err := m.add(entry); err != nil {
		return Entry{}, err
	}

	return entry, nil
}

// parse normalizes path, reusing the result of an earlier parse of the same path.
// Normalization is memoised per path rather than per endpoint on purpose: the
// anonymous regex counter is mapper-wide, so re-parsing one path for a second
// HTTP method would mint fresh placeholder names and split what should be a
// single PathItem into two.
func (m *Mapper) parse(path string) (*NormalizedPath, error) {
	if normalized, ok := m.parsedPaths[path]; ok {
		return normalized, nil
	}

	normalized, err := m.parser.Parse(path)

	if err != nil {
		return nil, err
	}

	m.parsedPaths[path] = normalized
	// An already normalized path maps onto itself, so that a later lookup by the
	// normalized form resolves to the same PathItem instead of re-parsing it.
	m.parsedPaths[normalized.path] = normalized

	return normalized, nil
}

// parametersFor returns the path parameters shared by every endpoint on the
// normalized path, creating them on first use.
func (m *Mapper) parametersFor(normalized *NormalizedPath) *openapi3.Parameters {
	if params, ok := m.pathParams[normalized.path]; ok {
		return params
	}

	params := openapi3.NewParameters()
	extractParametersFromPath(&params, normalized.ParameterRefs())
	m.pathParams[normalized.path] = &params

	return &params
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
		return operationId(path, method)
	}

	return opId
}

var emptyStringRe = regexp.MustCompile(`^\s*$`)
