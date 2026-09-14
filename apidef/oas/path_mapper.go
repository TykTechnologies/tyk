package oas

import (
	"errors"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/internal/pathnormalizer"
)

// pathMapper places a Tyk Classic endpoint in an OAS document and reports the
// operation ID the Tyk extension keys its middleware by.
//
// There are deliberately two implementations, and they are kept apart rather
// than folded into one path with a flag.
//
// legacyPathMapper reproduces the conversion Tyk has always performed. Its
// quirks are load-bearing: customers route on the behaviour that falls out of
// them, so it is a contract rather than an implementation, and it must not
// change. It is the default, so a caller that says nothing keeps it.
//
// normalizingPathMapper hands placeholder naming to pathnormalizer, which keeps
// names unique across the whole document. It is reached only from the
// Classic-to-OAS migration, where a user is deliberately converting an API and
// a changed result is the point.
type pathMapper interface {
	// mapEndpoint returns the operation ID for a Classic path and method,
	// creating the OAS path item and operation as needed.
	//
	// ok is false when the endpoint could not be placed at all, and the caller
	// must then skip it rather than carry on with an empty operation ID: that
	// would key its middleware under "" in the Tyk extension, merging every
	// such endpoint into one, and the helpers that look the operation back up
	// would dereference a nil path item. What went wrong is recorded by the
	// mapper, so the caller has nothing to report itself.
	mapEndpoint(s *OAS, path, method string) (operationID string, ok bool)
}

// fallbackPathMapper places an endpoint with primary, and with fallback when
// primary cannot place it.
//
// The ordinary fill cycle must not drop an endpoint it would previously have
// placed, however odd its path, so a failure there is a reason to fall back
// rather than to skip. Migration wants the opposite and uses the normalizing
// mapper directly, so that it can report what it could not convert.
type fallbackPathMapper struct {
	primary  pathMapper
	fallback pathMapper
}

func (m *fallbackPathMapper) mapEndpoint(s *OAS, path, method string) (string, bool) {
	if operationID, ok := m.primary.mapEndpoint(s, path, method); ok {
		return operationID, true
	}

	return m.fallback.mapEndpoint(s, path, method)
}

// legacyPathMapper is the frozen conversion. Do not change its behaviour: see
// pathMapper. It cannot fail, which is why only the normalizing mapper reports
// errors.
type legacyPathMapper struct{}

func (*legacyPathMapper) mapEndpoint(s *OAS, path, method string) (string, bool) {
	// Always ok: the legacy conversion places every endpoint somewhere, however
	// odd its path, and that is part of the behaviour being preserved.
	return s.getOperationID(path, method), true
}

// normalizingPathMapper converts Classic paths through pathnormalizer, so that
// two endpoints differing only by their regex keep placeholder names of their
// own instead of one overwriting the other.
type normalizingPathMapper struct {
	mapper *pathnormalizer.Mapper
	errs   []error
}

// newNormalizingPathMapper seeds a mapper with the paths the document already
// carries, so placeholder names it hands out never land on one in use and a
// conversion onto an earlier conversion's output resolves to the paths already
// there.
func newNormalizingPathMapper(paths *openapi3.Paths) (*normalizingPathMapper, error) {
	mapper, err := pathnormalizer.NewMapper(paths)
	if err != nil {
		return nil, fmt.Errorf("cannot read the existing paths of this API: %w", err)
	}

	return &normalizingPathMapper{mapper: mapper}, nil
}

func (m *normalizingPathMapper) mapEndpoint(s *OAS, path, method string) (string, bool) {
	entry, err := m.mapper.FindOrCreate(path, method)

	if err != nil {
		// Migration is a deliberate act, so an endpoint that cannot be converted
		// is reported rather than quietly carried over in some other shape. The
		// caller decides what to do about it; see OAS.fillForMigration.
		m.errs = append(m.errs, fmt.Errorf("endpoint %s %s cannot be converted: %w", method, path, err))

		// This is the point at which an endpoint stops being part of the
		// document, so it is recorded here as well as reported upwards. A
		// caller that ever drops the returned error would otherwise leave the
		// endpoint gone with nothing anywhere to say so.
		log.WithError(err).Errorf("dropping endpoint %s %s from the migrated API, its path cannot be converted", method, path)

		return "", false
	}

	pathItem := s.getOrCreatePathItem(entry.Normalized)

	// Extend a copy, so a path carrying no regex keeps its parameters unset
	// rather than gaining an empty list.
	params := pathItem.Parameters
	entry.ExtendPathParameters(&params)

	if len(params) > 0 {
		pathItem.Parameters = params
	}

	return getOrCreateOperation(pathItem, method, entry.OperationID).OperationID, true
}

// err reports every endpoint the mapper could not convert, nil when it converted
// all of them.
func (m *normalizingPathMapper) err() error { return errors.Join(m.errs...) }

// getOrCreatePathItem returns the path item stored under oasPath, creating an
// empty one when the document does not carry it yet.
func (s *OAS) getOrCreatePathItem(oasPath string) *openapi3.PathItem {
	if pathItem := s.Paths.Value(oasPath); pathItem != nil {
		return pathItem
	}

	pathItem := &openapi3.PathItem{}
	s.Paths.Set(oasPath, pathItem)

	return pathItem
}

// getOrCreateOperation returns the operation for method on pathItem, creating it
// when absent, and gives it defaultID when it carries no ID of its own. An ID
// already set is left alone, since it may have been written by hand.
func getOrCreateOperation(pathItem *openapi3.PathItem, method, defaultID string) *openapi3.Operation {
	operation := pathItem.GetOperation(method)

	if operation == nil {
		operation = &openapi3.Operation{
			Responses: openapi3.NewResponses(),
		}

		pathItem.SetOperation(method, operation)
	}

	if operation.OperationID == "" {
		operation.OperationID = defaultID
	}

	return operation
}

// ensurePaths guarantees a non-nil Paths. A valid OAS document needs one even
// when it carries no paths at all, and the normalizing mapper is seeded from it
// before any path is filled.
func (s *OAS) ensurePaths() *openapi3.Paths {
	if s.Paths == nil {
		s.Paths = openapi3.NewPaths()
	}

	return s.Paths
}

// usesGeneratedPlaceholders reports whether the document holds a path parameter
// migration generated: customRegexN carrying a regex. Only migration mints
// those names together with a pattern.
func (s *OAS) usesGeneratedPlaceholders() bool {
	if s.Paths == nil {
		return false
	}

	for _, pathItem := range s.Paths.Map() {
		for _, ref := range pathItem.Parameters {
			if ref == nil || ref.Value == nil || ref.Value.In != openapi3.ParameterInPath {
				continue
			}

			if !pathnormalizer.IsGeneratedName(ref.Value.Name) {
				continue
			}

			if schema := ref.Value.Schema; schema != nil && schema.Value != nil && schema.Value.Pattern != "" {
				return true
			}
		}
	}

	return false
}

// ordinaryPathMapper picks how Fill places endpoints for this document.
//
// The legacy conversion cannot read a document migration produced. It numbers
// placeholders from one for every path it is given, so two Classic endpoints
// differing only by their regex both resolve to {customRegex1}: the second one
// lands on the first one's operation and writes its middleware there, which is
// how a mock response body ends up on the wrong endpoint. The normalizing
// mapper resolves an endpoint by the operation ID migration gave it, so it
// lands where it belongs.
//
// Every other document keeps the legacy conversion, which is the frozen
// contract, and a document this cannot place still falls back to it, so nothing
// that used to be placed is dropped.
func (s *OAS) ordinaryPathMapper() pathMapper {
	if !s.usesGeneratedPlaceholders() {
		return &legacyPathMapper{}
	}

	mapper, err := newNormalizingPathMapper(s.Paths)
	if err != nil {
		log.WithError(err).Error("cannot read the generated paths of this API, falling back to the legacy conversion")
		return &legacyPathMapper{}
	}

	return &fallbackPathMapper{primary: mapper, fallback: &legacyPathMapper{}}
}
