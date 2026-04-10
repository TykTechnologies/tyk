package log

import (
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/maps"
)

// LoadTranslations takes a map[string]interface and flattens it to map[string]string.
// Because translations have been loaded - we internally override log the formatter.
// Nested entries are accessible using dot notation.
//
// Example:   `{"foo": {"bar": "baz"}}`
// Flattened: `foo.bar: baz`
func LoadTranslations(thing map[string]interface{}) {
	// This wraps the existing formatter if translations are loaded.
	log.Formatter = &TranslationFormatter{log.Formatter}
	translations, _ = maps.Flatten(thing)
}

// TranslationFormatter handles message reformatting with translations.
type TranslationFormatter struct {
	logrus.Formatter
}

// Format will translate the log message based on the message code. This is
// a HTTP response code if provided. The message is usually just "Finished"
// for those cases, this would likely produce a better log message.
func (t *TranslationFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if code, ok := entry.Data["code"]; ok {
		if translation, ok := translations[code.(string)]; ok {
			entry.Message = translation
		}
	}
	return t.Formatter.Format(entry)
}
