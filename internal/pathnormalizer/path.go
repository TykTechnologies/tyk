package pathnormalizer

import (
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	notFound = -1
)

type NormalizedPath struct {
	path       string
	parameters []*openapi3.Parameter
}

func newNormalizedPath(parts []pathPart) *NormalizedPath {
	var sb strings.Builder
	var np NormalizedPath

	for _, part := range parts {
		sb.WriteString(part.normalize())

		if part.parameter != nil {
			np.parameters = append(np.parameters, part.parameter)
		}
	}

	np.path = sb.String()

	return &np
}

// HasParams returns true if path has path-based parameters.
func (o NormalizedPath) HasParams() bool {
	return len(o.parameters) != 0
}

// Parameters slices of path-based params.
func (o NormalizedPath) Parameters() []*openapi3.Parameter {
	return o.parameters
}

// ParameterRefs slices of path-based params.
func (o NormalizedPath) ParameterRefs() []*openapi3.ParameterRef {
	res := make([]*openapi3.ParameterRef, 0, len(o.parameters))

	for _, p := range o.parameters {
		res = append(res, &openapi3.ParameterRef{Value: p})
	}

	return res
}

// operationId builds an operation id from a raw, not yet normalized path.
// NormalizedPath.OperationId is the equivalent for a path already normalized.
func operationId(path, method string) string {
	return strings.TrimPrefix(path, string(slash)) + strings.ToUpper(method)
}

// OperationId create operation id by method name.
func (o NormalizedPath) OperationId(method string) string {
	return o.RawOpIdPrefix() + strings.ToUpper(method)
}

// RawOpIdPrefix returns prefix.
func (o NormalizedPath) RawOpIdPrefix() string {
	return strings.TrimPrefix(o.path, string(slash))
}

// generatedName matches the placeholder names Parser mints for regex segments
// it finds in a user-defined path. A name the user chose never matches.
var generatedName = regexp.MustCompile(`^` + regexp.QuoteMeta(RePrefix) + `\d+$`)

// Denormalize turns a normalized path back into the user-defined path it was
// generated from, and is the inverse of what Parser does to a path.
//
// Normalizing replaces each regex segment with a generated placeholder and
// moves the regex onto that placeholder's parameter, so /users/[a-z]+ becomes
// /users/{customRegex1} carrying pattern [a-z]+. Anything reading the path
// alone, Tyk Classic routing among them, sees only a placeholder and treats it
// as "one segment, any value", which makes every regex endpoint on a path match
// the same requests. Putting the regex back into the path is what keeps them
// apart, and only the raw form does it: {name:regex} is read as a placeholder
// too.
//
// Only placeholders this package mints are substituted. A parameter the user
// named is left alone, since the name means something to them and the shape of
// their path is theirs to choose.
func Denormalize(path string, params openapi3.Parameters) string {
	if len(params) == 0 || !strings.ContainsRune(path, curlyBraceLeft) {
		return path
	}

	denormalized := path

	for _, ref := range params {
		if ref == nil || ref.Value == nil || ref.Value.In != openapi3.ParameterInPath {
			continue
		}

		if !generatedName.MatchString(ref.Value.Name) {
			continue
		}

		schema := ref.Value.Schema
		if schema == nil || schema.Value == nil || schema.Value.Pattern == "" {
			continue
		}

		denormalized = strings.ReplaceAll(denormalized,
			string(curlyBraceLeft)+ref.Value.Name+string(curlyBraceRight),
			schema.Value.Pattern)
	}

	return denormalized
}

// IsGeneratedName reports whether name is one this package mints for an
// anonymous regex, rather than one the user chose.
func IsGeneratedName(name string) bool {
	return generatedName.MatchString(name)
}
