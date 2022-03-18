package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSerializer_Encode(t *testing.T) {
	tcs := []struct{
		testName string
		serializer AnalyticsSerializer
	}{
		{
			testName: "msgpack",
			serializer: NewAnalyticsSerializer(MSGP_SERIALIZER),
		},
		{
			testName: "gotiny",
			serializer: NewAnalyticsSerializer(GOTINY_SERIALIZER),
		},
	}

	for _,tc := range tcs{
		t.Run(tc.testName, func(t *testing.T){
			record := AnalyticsRecord{
				APIID: "api_1",
				OrgID: "org_1",
			}

			bytes, err := tc.serializer.Encode(&record)

			assert.Equal(t, nil, err)
			assert.NotEqual(t, 0,len(bytes))
		})
	}
}

func TestSerializer_Decode(t *testing.T) {
	tcs := []struct{
		testName string
		serializer AnalyticsSerializer
	}{
		{
			testName: "msgpack",
			serializer: NewAnalyticsSerializer(MSGP_SERIALIZER),
		},
		{
			testName: "gotiny",
			serializer: NewAnalyticsSerializer(GOTINY_SERIALIZER),
		},
	}

	for _,tc := range tcs{
		t.Run(tc.testName, func(t *testing.T){
			record := AnalyticsRecord{
				APIID: "api_1",
				OrgID: "org_1",
			}

			bytes, _ := tc.serializer.Encode(&record)
			newRecord := &AnalyticsRecord{}

			tc.serializer.Decode(bytes, newRecord)
			assert.ObjectsAreEqualValues(record,newRecord)
		})
	}
}

func TestSerializer_GetSuffix(t *testing.T) {
	tcs := []struct{
		testName string
		serializer AnalyticsSerializer
		expectedSuffix string
	}{
		{
			testName: "msgpack",
			serializer: NewAnalyticsSerializer(MSGP_SERIALIZER),
			expectedSuffix : "",
		},
		{
			testName: "gotiny",
			serializer: NewAnalyticsSerializer(GOTINY_SERIALIZER),
			expectedSuffix: "_gotiny",
		},
	}

	for _,tc := range tcs{
		t.Run(tc.testName, func(t *testing.T){
			assert.Equal(t, tc.expectedSuffix,tc.serializer.GetSuffix())
		})
	}
}