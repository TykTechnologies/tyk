package log

import "github.com/sirupsen/logrus"

type FieldMap struct {
	fields map[string]string
}

func NewFieldMap(fMap logrus.FieldMap) FieldMap {
	m := make(map[string]string, len(fMap))

	for k, v := range fMap {
		m[string(k)] = v
	}

	return FieldMap{fields: m}
}

func (f FieldMap) Resolve(field string) string {
	if len(f.fields) == 0 {
		return field
	}

	if k, ok := f.fields[field]; ok {
		return k
	}

	return field
}
