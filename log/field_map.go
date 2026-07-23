package log

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
)

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

func (f *FieldMap) Resolve(field string) string {
	if len(f.fields) == 0 {
		return field
	}

	if k, ok := f.fields[field]; ok {
		return k
	}

	return field
}

func (f *FieldMap) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	f.fields = m
	return nil
}

func (f FieldMap) MarshalJSON() ([]byte, error) {
	if len(f.fields) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(f.fields)
}
