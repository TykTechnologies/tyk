package paramextractor

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var (
	ErrInvalidPattern = errors.New("invalid pattern")
	ErrNoMatch        = errors.New("no match found")
)

// Extractor defines the interface for extracting parameters from HTTP requests
type Extractor interface {
	Extract(r *http.Request, pattern string) (map[string]string, error)
}

// Type represents the type of parameter extraction strategy
type Type struct {
	name string
}

var (
	// StrictExtractor matches exact path segments
	StrictExtractor = Type{"strict"}
	// PrefixExtractor matches path segments with prefix pattern
	PrefixExtractor = Type{"prefix"}
	// SuffixExtractor matches path segments with suffix pattern
	SuffixExtractor = Type{"suffix"}
	// GlobExtractor matches path segments with glob pattern
	GlobExtractor = Type{"glob"}
)

// NewParamExtractor creates a new parameter extractor based on the provided config
func NewParamExtractor(typ Type) Extractor {
	switch typ {
	case PrefixExtractor:
		return &prefixExtractor{}
	case SuffixExtractor:
		return &suffixExtractor{}
	case GlobExtractor:
		return &globExtractor{}
	case StrictExtractor:
		return &strictExtractor{}
	default:
		return &strictExtractor{}
	}
}

// NewParamExtractorFromFlags creates a new parameter extractor based on prefix and suffix flags
// This factory method determines the extractor type based on the combination of flags:
// - If both prefix and suffix are true: use GlobExtractor (most flexible)
// - If only prefix is true: use PrefixExtractor
// - If only suffix is true: use SuffixExtractor
// - If neither is true: use StrictExtractor (most restrictive)
func NewParamExtractorFromFlags(prefix, suffix bool) Extractor {
	if prefix && suffix {
		// If both flags are true, use the most flexible matcher (glob)
		return &globExtractor{}
	} else if prefix {
		return &prefixExtractor{}
	} else if suffix {
		return &suffixExtractor{}
	} else {
		// Default to strict matching if no flags are set
		return &strictExtractor{}
	}
}

// baseExtractor contains common functionality for all extractors
type baseExtractor struct{}

// parsePattern extracts parameter names from a pattern string
func (b *baseExtractor) parsePattern(pattern string) []string {
	segments := strings.Split(pattern, "/")
	var params []string

	for _, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			// Extract parameter name without braces
			paramName := segment[1 : len(segment)-1]
			params = append(params, paramName)
		}
	}

	return params
}

// matchSegments matches path segments against pattern segments and extracts parameters
func (b *baseExtractor) matchSegments(patternSegments, pathSegments []string, strict bool) (map[string]string, error) {
	params := make(map[string]string)

	// For strict matching, the number of segments must match
	if strict && len(patternSegments) != len(pathSegments) {
		return nil, ErrNoMatch
	}

	// For prefix matching, the path must have at least as many segments as the pattern
	if !strict && len(pathSegments) < len(patternSegments) {
		return nil, ErrNoMatch
	}

	// Match segments and extract parameters
	for i, patternSegment := range patternSegments {
		if i >= len(pathSegments) {
			return nil, ErrNoMatch
		}

		pathSegment := pathSegments[i]

		if strings.HasPrefix(patternSegment, "{") && strings.HasSuffix(patternSegment, "}") {
			// Extract parameter name without braces
			paramName := patternSegment[1 : len(patternSegment)-1]
			params[paramName] = pathSegment
		} else if patternSegment != pathSegments[i] {
			// If not a parameter and segments don't match, return no match
			return nil, ErrNoMatch
		}
	}

	return params, nil
}

// strictExtractor implements strict path matching
type strictExtractor struct {
	baseExtractor
}

func (e *strictExtractor) Extract(r *http.Request, pattern string) (map[string]string, error) {
	path := strings.Trim(r.URL.Path, "/")
	pattern = strings.Trim(pattern, "/")

	patternSegments := strings.Split(pattern, "/")
	pathSegments := strings.Split(path, "/")

	return e.matchSegments(patternSegments, pathSegments, true)
}

// prefixExtractor implements prefix path matching
type prefixExtractor struct {
	baseExtractor
}

func (e *prefixExtractor) Extract(r *http.Request, pattern string) (map[string]string, error) {
	path := strings.Trim(r.URL.Path, "/")
	pattern = strings.Trim(pattern, "/")

	patternSegments := strings.Split(pattern, "/")
	pathSegments := strings.Split(path, "/")

	return e.matchSegments(patternSegments, pathSegments, false)
}

// suffixExtractor implements suffix path matching
type suffixExtractor struct {
	baseExtractor
}

func (e *suffixExtractor) Extract(r *http.Request, pattern string) (map[string]string, error) {
	path := strings.Trim(r.URL.Path, "/")
	pattern = strings.Trim(pattern, "/")

	patternSegments := strings.Split(pattern, "/")
	pathSegments := strings.Split(path, "/")

	// For suffix matching, we need to align the segments from the end
	if len(pathSegments) < len(patternSegments) {
		return nil, ErrNoMatch
	}

	// Adjust path segments to align with the end of the pattern
	offset := len(pathSegments) - len(patternSegments)
	alignedPathSegments := pathSegments[offset:]

	return e.matchSegments(patternSegments, alignedPathSegments, true)
}

// globExtractor implements glob pattern matching
type globExtractor struct {
	baseExtractor
}

func (e *globExtractor) Extract(r *http.Request, pattern string) (map[string]string, error) {
	path := r.URL.Path

	// Convert glob pattern to regex
	regexPattern := e.globToRegex(pattern)
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, ErrInvalidPattern
	}

	// Find parameter names in the pattern
	paramNames := e.parsePattern(pattern)

	// Match the path against the regex
	matches := re.FindStringSubmatch(path)
	if matches == nil || len(matches) < len(paramNames)+1 {
		return nil, ErrNoMatch
	}

	// Extract parameters from regex matches
	params := make(map[string]string)
	for i, name := range paramNames {
		params[name] = matches[i+1]
	}

	return params, nil
}

// globToRegex converts a glob pattern with {param} to a regex pattern
func (e *globExtractor) globToRegex(pattern string) string {
	// Escape special regex characters
	pattern = regexp.QuoteMeta(pattern)

	// Replace {param} with regex capture groups
	re := regexp.MustCompile(`\\\{([^{}]+)\\\}`)
	pattern = re.ReplaceAllString(pattern, "([^/]+)")

	// Ensure the pattern matches the entire path
	return "^" + pattern + "$"
}
