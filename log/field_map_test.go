package log_test

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/log"
)

func TestFieldMap_Resolve(t *testing.T) {
	tests := []struct {
		name       string
		fieldMap   log.FieldMap
		inputField string
		want       string
	}{
		{
			name:       "Uninitialized map",
			fieldMap:   log.NewFieldMap(logrus.FieldMap{}),
			inputField: "msg",
			want:       "msg",
		},
		{
			name:       "Empty initialized map",
			fieldMap:   log.NewFieldMap(logrus.FieldMap{}),
			inputField: "msg",
			want:       "msg",
		},
		{
			name: "Existing mapping resolved",
			fieldMap: log.NewFieldMap(logrus.FieldMap{
				logrus.FieldKeyMsg: "message",
			}),
			inputField: "msg",
			want:       "message",
		},
		{
			name: "Missing mapping returns original field",
			fieldMap: log.NewFieldMap(logrus.FieldMap{
				logrus.FieldKeyMsg: "message",
			}),
			inputField: "time",
			want:       "time",
		},
		{
			name: "Empty string field resolved",
			fieldMap: log.NewFieldMap(logrus.FieldMap{
				"": "empty_key",
			}),
			inputField: "",
			want:       "empty_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fieldMap.Resolve(tt.inputField)
			require.Equal(t, tt.want, got)
		})
	}
}
