package jsonschema

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	jptr "github.com/qri-io/jsonpointer"
)

const (
	hostname       string = `^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`
	unescapedTilda        = `\~[^01]`
	endingTilda           = `\~$`
	schemePrefix          = `^[^\:]+\:`
	uriTemplate           = `\{[^\{\}\\]*\}`
)

var (
	// emailPattern           = regexp.MustCompile(email)
	hostnamePattern        = regexp.MustCompile(hostname)
	unescaptedTildaPattern = regexp.MustCompile(unescapedTilda)
	endingTildaPattern     = regexp.MustCompile(endingTilda)
	schemePrefixPattern    = regexp.MustCompile(schemePrefix)
	uriTemplatePattern     = regexp.MustCompile(uriTemplate)

	disallowedIdnChars = map[string]bool{"\u0020": true, "\u002D": true, "\u00A2": true, "\u00A3": true, "\u00A4": true, "\u00A5": true, "\u034F": true, "\u0640": true, "\u07FA": true, "\u180B": true, "\u180C": true, "\u180D": true, "\u200B": true, "\u2060": true, "\u2104": true, "\u2108": true, "\u2114": true, "\u2117": true, "\u2118": true, "\u211E": true, "\u211F": true, "\u2123": true, "\u2125": true, "\u2282": true, "\u2283": true, "\u2284": true, "\u2285": true, "\u2286": true, "\u2287": true, "\u2288": true, "\u2616": true, "\u2617": true, "\u2619": true, "\u262F": true, "\u2638": true, "\u266C": true, "\u266D": true, "\u266F": true, "\u2752": true, "\u2756": true, "\u2758": true, "\u275E": true, "\u2761": true, "\u2775": true, "\u2794": true, "\u2798": true, "\u27AF": true, "\u27B1": true, "\u27BE": true, "\u3004": true, "\u3012": true, "\u3013": true, "\u3020": true, "\u302E": true, "\u302F": true, "\u3031": true, "\u3032": true, "\u3035": true, "\u303B": true, "\u3164": true, "\uFFA0": true}
)

// Format defines the format JSON Schema keyword
type Format string

// NewFormat allocates a new Format keyword
func NewFormat() Keyword {
	return new(Format)
}

// Register implements the Keyword interface for Format
func (f *Format) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Format
func (f *Format) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for Format
func (f Format) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Format] Validating")
	var err error
	if str, ok := data.(string); ok {
		switch f {
		case "date-time":
			err = isValidDateTime(str)
		case "date":
			err = isValidDate(str)
		case "email":
			err = isValidEmail(str)
		case "hostname":
			err = isValidHostname(str)
		case "idn-email":
			err = isValidIDNEmail(str)
		case "idn-hostname":
			err = isValidIDNHostname(str)
		case "ipv4":
			err = isValidIPv4(str)
		case "ipv6":
			err = isValidIPv6(str)
		case "iri-reference":
			err = isValidIriRef(str)
		case "iri":
			err = isValidIri(str)
		case "json-pointer":
			err = isValidJSONPointer(str)
		case "regex":
			err = isValidRegex(str)
		case "relative-json-pointer":
			err = isValidRelJSONPointer(str)
		case "time":
			err = isValidTime(str)
		case "uri-reference":
			err = isValidURIRef(str)
		case "uri-template":
			err = isValidURITemplate(str)
		case "uri":
			err = isValidURI(str)
		default:
			err = nil
		}
		if err != nil {
			currentState.AddError(data, fmt.Sprintf("invalid %s: %s", f, err.Error()))
		}
	}
}

// A string instance is valid against "date-time" if it is a valid
// representation according to the "date-time" production derived
// from RFC 3339, section 5.6 [RFC3339]
// https://tools.ietf.org/html/rfc3339#section-5.6
func isValidDateTime(dateTime string) error {
	if _, err := time.Parse(time.RFC3339, strings.ToUpper(dateTime)); err != nil {
		return fmt.Errorf("date-time incorrectly Formatted: %s", err.Error())
	}
	return nil
}

// A string instance is valid against "date" if it is a valid
// representation according to the "full-date" production derived
// from RFC 3339, section 5.6 [RFC3339]
// https://tools.ietf.org/html/rfc3339#section-5.6
func isValidDate(date string) error {
	arbitraryTime := "T08:30:06.283185Z"
	dateTime := fmt.Sprintf("%s%s", date, arbitraryTime)
	return isValidDateTime(dateTime)
}

// A string instance is valid against "email" if it is a valid
// representation as defined by RFC 5322, section 3.4.1 [RFC5322].
// https://tools.ietf.org/html/rfc5322#section-3.4.1
func isValidEmail(email string) error {
	// if !emailPattern.MatchString(email) {
	// 	return fmt.Errorf("invalid email Format")
	// }
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("email address incorrectly Formatted: %s", err.Error())
	}
	return nil
}

// A string instance is valid against "hostname" if it is a valid
// representation as defined by RFC 1034, section 3.1 [RFC1034],
// including host names produced using the Punycode algorithm
// specified in RFC 5891, section 4.4 [RFC5891].
// https://tools.ietf.org/html/rfc1034#section-3.1
// https://tools.ietf.org/html/rfc5891#section-4.4
func isValidHostname(hostname string) error {
	if !hostnamePattern.MatchString(hostname) || len(hostname) > 255 {
		return fmt.Errorf("invalid hostname string")
	}
	return nil
}

// A string instance is valid against "idn-email" if it is a valid
// representation as defined by RFC 6531 [RFC6531]
// https://tools.ietf.org/html/rfc6531
func isValidIDNEmail(idnEmail string) error {
	if _, err := mail.ParseAddress(idnEmail); err != nil {
		return fmt.Errorf("email address incorrectly Formatted: %s", err.Error())
	}
	return nil
}

// A string instance is valid against "hostname" if it is a valid
// representation as defined by either RFC 1034 as for hostname, or
// an internationalized hostname as defined by RFC 5890, section
// 2.3.2.3 [RFC5890].
// https://tools.ietf.org/html/rfc1034
// https://tools.ietf.org/html/rfc5890#section-2.3.2.3
// https://pdfs.semanticscholar.org/9275/6bcecb29d3dc407e23a997b256be6ff4149d.pdf
func isValidIDNHostname(idnHostname string) error {
	if len(idnHostname) > 255 {
		return fmt.Errorf("invalid idn hostname string")
	}
	for _, r := range idnHostname {
		s := string(r)
		if disallowedIdnChars[s] {
			return fmt.Errorf("invalid hostname: contains illegal character %#U", r)
		}
	}
	return nil
}

// A string instance is valid against "ipv4" if it is a valid
// representation of an IPv4 address according to the "dotted-quad"
// ABNF syntax as defined in RFC 2673, section 3.2 [RFC2673].
// https://tools.ietf.org/html/rfc2673#section-3.2
func isValidIPv4(ipv4 string) error {
	parsedIP := net.ParseIP(ipv4)
	hasDots := strings.Contains(ipv4, ".")
	if !hasDots || parsedIP == nil {
		return fmt.Errorf("invalid IPv4 address")
	}
	return nil
}

// A string instance is valid against "ipv6" if it is a valid
// representation of an IPv6 address as defined in RFC 4291, section
// 2.2 [RFC4291].
// https://tools.ietf.org/html/rfc4291#section-2.2
func isValidIPv6(ipv6 string) error {
	parsedIP := net.ParseIP(ipv6)
	hasColons := strings.Contains(ipv6, ":")
	if !hasColons || parsedIP == nil {
		return fmt.Errorf("invalid IPv4 address")
	}
	return nil
}

// A string instance is a valid against "iri-reference" if it is a
// valid IRI Reference (either an IRI or a relative-reference),
// according to [RFC3987].
// https://tools.ietf.org/html/rfc3987
func isValidIriRef(iriRef string) error {
	return isValidURIRef(iriRef)
}

// A string instance is a valid against "iri" if it is a valid IRI,
// according to [RFC3987].
// https://tools.ietf.org/html/rfc3987
func isValidIri(iri string) error {
	return isValidURI(iri)
}

// A string instance is a valid against "json-pointer" if it is a
// valid JSON string representation of a JSON Pointer, according to
// RFC 6901, section 5 [RFC6901].
// https://tools.ietf.org/html/rfc6901#section-5
func isValidJSONPointer(jsonPointer string) error {
	if len(jsonPointer) == 0 {
		return nil
	}
	if jsonPointer[0] != '/' {
		return fmt.Errorf("non-empty references must begin with a '/' character")
	}
	str := jsonPointer[1:]
	if unescaptedTildaPattern.MatchString(str) {
		return fmt.Errorf("unescaped tilda error")
	}
	if endingTildaPattern.MatchString(str) {
		return fmt.Errorf("unescaped tilda error")
	}
	return nil
}

// A string instance is a valid against "regex" if it is a valid
// regular expression according to the ECMA 262 [ecma262] regular
// expression dialect. Implementations that validate Formats MUST
// accept at least the subset of ECMA 262 defined in the Regular
// Expressions [regexInterop] section of this specification, and
// SHOULD accept all valid ECMA 262 expressions.
// http://www.ecma-international.org/publications/files/ECMA-ST/Ecma-262.pdf
// http://json-schema.org/latest/jsoxn-schema-validation.html#regexInterop
// https://tools.ietf.org/html/rfc7159
func isValidRegex(regex string) error {
	if _, err := regexp.Compile(regex); err != nil {
		return fmt.Errorf("invalid regex expression")
	}
	return nil
}

// A string instance is a valid against "relative-json-pointer" if it
// is a valid Relative JSON Pointer [relative-json-pointer].
// https://tools.ietf.org/html/draft-handrews-relative-json-pointer-00
func isValidRelJSONPointer(relJSONPointer string) error {
	parts := strings.Split(relJSONPointer, "/")
	if len(parts) == 1 {
		parts = strings.Split(relJSONPointer, "#")
	}
	if i, err := strconv.Atoi(parts[0]); err != nil || i < 0 {
		return fmt.Errorf("RJP must begin with positive integer")
	}
	//skip over first part
	str := relJSONPointer[len(parts[0]):]
	if len(str) > 0 && str[0] == '#' {
		return nil
	}
	return isValidJSONPointer(str)
}

// A string instance is valid against "time" if it is a valid
// representation according to the "full-time" production derived
// from RFC 3339, section 5.6 [RFC3339]
// https://tools.ietf.org/html/rfc3339#section-5.6
func isValidTime(time string) error {
	arbitraryDate := "1963-06-19"
	dateTime := fmt.Sprintf("%sT%s", arbitraryDate, time)
	return isValidDateTime(dateTime)
	return nil
}

// A string instance is a valid against "uri-reference" if it is a
// valid URI Reference (either a URI or a relative-reference),
// according to [RFC3986].
// https://tools.ietf.org/html/rfc3986
func isValidURIRef(uriRef string) error {
	if _, err := url.Parse(uriRef); err != nil {
		return fmt.Errorf("uri incorrectly Formatted: %s", err.Error())
	}
	if strings.Contains(uriRef, "\\") {
		return fmt.Errorf("invalid uri")
	}
	return nil
}

// A string instance is a valid against "uri-template" if it is a
// valid URI Template (of any level), according to [RFC6570]. Note
// that URI Templates may be used for IRIs; there is no separate IRI
// Template specification.
// https://tools.ietf.org/html/rfc6570
func isValidURITemplate(uriTemplate string) error {
	arbitraryValue := "aaa"
	uriRef := uriTemplatePattern.ReplaceAllString(uriTemplate, arbitraryValue)
	if strings.Contains(uriRef, "{") || strings.Contains(uriRef, "}") {
		return fmt.Errorf("invalid uri template")
	}
	return isValidURIRef(uriRef)
}

// A string instance is a valid against "uri" if it is a valid URI,
// according to [RFC3986].
// https://tools.ietf.org/html/rfc3986
func isValidURI(uri string) error {
	if _, err := url.Parse(uri); err != nil {
		return fmt.Errorf("uri incorrectly Formatted: %s", err.Error())
	}
	if !schemePrefixPattern.MatchString(uri) {
		return fmt.Errorf("uri missing scheme prefix")
	}
	return nil
}
