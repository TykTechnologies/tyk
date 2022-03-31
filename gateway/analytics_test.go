package gateway

import (
	"github.com/TykTechnologies/tyk/analytics"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestGeoIPLookup(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testCases := [...]struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"foobar", true},
		{"1.2.3.4", false},
	}
	for _, tc := range testCases {
		_, err := geoIPLookup(tc.in, ts.Gw)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("geoIPLookup(%q) did not error", tc.in)
		case !tc.wantErr && err != nil:
			t.Errorf("geoIPLookup(%q) errored", tc.in)
		}
	}
}

func TestURLReplacer(t *testing.T) {

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
		globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	})
	defer ts.Close()
	globalConf := ts.Gw.GetConfig()

	recordUUID1 := analytics.Record{Path: "/15873a748894492162c402d67e92283b/search"}
	recordUUID2 := analytics.Record{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
	recordUUID3 := analytics.Record{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordUUID4 := analytics.Record{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordID1 := analytics.Record{Path: "/widgets/123456/getParams"}
	recordCust := analytics.Record{Path: "/widgets/123456/getParams/ihatethisstring"}

	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = ts.Gw.initNormalisationPatterns()
	ts.Gw.SetConfig(globalConf)

	recordUUID1.NormalisePath(&globalConf)
	recordUUID2.NormalisePath(&globalConf)
	recordUUID3.NormalisePath(&globalConf)
	recordUUID4.NormalisePath(&globalConf)
	recordID1.NormalisePath(&globalConf)
	recordCust.NormalisePath(&globalConf)

	if recordUUID1.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID1.Path)
		t.Error(ts.Gw.GetConfig().AnalyticsConfig.NormaliseUrls)
	}

	if recordUUID2.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID2.Path)
	}

	if recordUUID3.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID3.Path)
	}

	if recordUUID4.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID4.Path)
	}

	if recordID1.Path != "/widgets/{id}/getParams" {
		t.Error("Path not altered, is:")
		t.Error(recordID1.Path)
	}

	if recordCust.Path != "/widgets/{id}/getParams/{var}" {
		t.Error("Path not altered, is:")
		t.Error(recordCust.Path)
	}
}

func BenchmarkURLReplacer(b *testing.B) {
	b.ReportAllocs()
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
		globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	})
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = ts.Gw.initNormalisationPatterns()
	ts.Gw.SetConfig(globalConf)

	for i := 0; i < b.N; i++ {
		recordUUID1 := analytics.Record{Path: "/15873a748894492162c402d67e92283b/search"}
		recordUUID2 := analytics.Record{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
		recordUUID3 := analytics.Record{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
		recordUUID4 := analytics.Record{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
		recordID1 := analytics.Record{Path: "/widgets/123456/getParams"}
		recordCust := analytics.Record{Path: "/widgets/123456/getParams/ihatethisstring"}

		recordUUID1.NormalisePath(&globalConf)
		recordUUID2.NormalisePath(&globalConf)
		recordUUID3.NormalisePath(&globalConf)
		recordUUID4.NormalisePath(&globalConf)
		recordID1.NormalisePath(&globalConf)
		recordCust.NormalisePath(&globalConf)
	}
}

func TestTagHeaders(t *testing.T) {
	req := TestReq(t, "GET", "/tagmeplease", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tag-Me", "1")
	req.Header.Set("X-Tag-Me2", "2")
	req.Header.Set("X-Tag-Me3", "3")
	req.Header.Set("X-Ignore-Me", "4")

	existingTags := []string{"first", "second"}
	existingTags = tagHeaders(req, []string{
		"x-tag-me",
		"x-tag-me2",
		"x-tag-me3"},
		existingTags)

	if len(existingTags) == 2 {
		t.Fatal("Existing tags have not been expanded")
	}

	if len(existingTags) != 5 {
		t.Fatalf("Wrong number of tags, got %v, wanted %v", len(existingTags), 5)
	}

	check := map[string]bool{
		"x-tag-me-1":  true,
		"x-tag-me2-2": true,
		"x-tag-me3-3": true,
	}

	for _, t := range existingTags {
		_, ok := check[t]
		if ok {
			delete(check, t)
		}
	}

	if len(check) != 0 {
		t.Fatalf("Header values not proerly set, got: %v, remnainder: %v", existingTags, check)
	}

}

func BenchmarkTagHeaders(b *testing.B) {
	b.ReportAllocs()

	req := TestReq(b, "GET", "/tagmeplease", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tag-Me", "1")
	req.Header.Set("X-Tag-Me2", "2")
	req.Header.Set("X-Tag-Me3", "3")
	req.Header.Set("X-Ignore-Me", "4")

	existingTags := []string{"first", "second"}

	var newExistingTags []string
	for i := 0; i < b.N; i++ {
		newExistingTags = tagHeaders(
			req,
			[]string{
				"x-tag-me",
				"x-tag-me2",
				"x-tag-me3",
			},
			existingTags,
		)
		if len(newExistingTags) == 2 {
			b.Fatal("Existing tags have not been expanded")
		}
	}
}
