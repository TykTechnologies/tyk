package escaper

import (
	htmltemplate "html/template"
	"mime"
	"net/http"

	"github.com/sirupsen/logrus"
)

type Type string

const (
	TypeSkip   Type = "skip"
	TypeLegacy Type = "legacy"
)

var allowedTypes = map[Type]struct{}{
	TypeSkip:   {},
	TypeLegacy: {},
}

const (
	XSkipEscaper = "X-Skip-Escaper"
	ContentType  = "Content-Type"
)

type FactoryOption func(*Factory)

type Factory struct {
	typ              Type
	logger           *logrus.Logger
	skipContentTypes map[string]struct{}
}

func WithLogger(logger *logrus.Logger) FactoryOption {
	return func(f *Factory) {
		f.logger = logger
	}
}

func WithType(typ Type) FactoryOption {
	return func(f *Factory) {
		f.typ = typ
	}
}

func WithSkipContentTypes(values ...string) FactoryOption {
	return func(f *Factory) {
		if f.skipContentTypes == nil {
			f.skipContentTypes = make(map[string]struct{}, len(values))
		}

		for _, h := range values {
			f.skipContentTypes[h] = struct{}{}
		}
	}
}

func NewFactory(options ...FactoryOption) *Factory {
	factory := Factory{
		typ:    TypeLegacy,
		logger: logrus.StandardLogger(),
	}

	for _, apply := range options {
		apply(&factory)
	}

	if len(factory.typ) == 0 {
		factory.typ = TypeLegacy
	}

	if _, ok := allowedTypes[factory.typ]; !ok {
		typ := factory.typ
		factory.typ = TypeLegacy
		factory.logger.WithField("type", typ).Warn("unknown type of escaper; rolling back to legacy escaper")
	}

	return &factory
}

func (f *Factory) Make(r *http.Request) Escaper {
	header := r.Header.Get(XSkipEscaper)
	switch {
	case len(header) > 0 && header != "0":
		return skipEscaper
	case f.typ == TypeSkip:
		return skipEscaper
	case f.hasSkipContentType(r):
		return skipEscaper
	default:
		return jsEscaper
	}
}

func (f *Factory) hasSkipContentType(r *http.Request) bool {
	if len(f.skipContentTypes) == 0 {
		return false
	}

	_, ok := f.skipContentTypes[f.contentType(r)]

	return ok
}

func (f *Factory) contentType(r *http.Request) string {
	h := r.Header.Get(ContentType)
	mediaType, _, err := mime.ParseMediaType(h)
	if err != nil {
		return h
	}
	return mediaType
}

type Escaper interface {
	Escape(msg string) string
}

type anonEscaper func(string) string

func (e anonEscaper) Escape(msg string) string {
	return e(msg)
}

var (
	jsEscaper   = anonEscaper(htmltemplate.JSEscapeString)
	skipEscaper = anonEscaper(func(s string) string {
		return s
	})
)
