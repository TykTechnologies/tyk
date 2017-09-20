package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestGeoIPLookup(t *testing.T) {
	testCases := [...]struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"foobar", true},
		{"1.2.3.4", false},
	}
	for _, tc := range testCases {
		_, err := geoIPLookup(tc.in)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("geoIPLookup(%q) did not error", tc.in)
		case !tc.wantErr && err != nil:
			t.Errorf("geoIPLookup(%q) errored", tc.in)
		}
	}
}

func TestURLReplacer(t *testing.T) {
	config.Global.AnalyticsConfig.NormaliseUrls.Enabled = true
	config.Global.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
	config.Global.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
	config.Global.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}

	recordUUID1 := AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
	recordUUID2 := AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
	recordUUID3 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordUUID4 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordID1 := AnalyticsRecord{Path: "/widgets/123456/getParams"}
	recordCust := AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

	config.Global.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = initNormalisationPatterns()

	recordUUID1.NormalisePath()
	recordUUID2.NormalisePath()
	recordUUID3.NormalisePath()
	recordUUID4.NormalisePath()
	recordID1.NormalisePath()
	recordCust.NormalisePath()

	if recordUUID1.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID1.Path)
		t.Error(config.Global.AnalyticsConfig.NormaliseUrls)
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

func TestTagHeaders(t *testing.T) {
	req := testReq(t, "GET", "/tagmeplease", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tag-Me", "1")
	req.Header.Set("X-Tag-Me2", "2")
	req.Header.Set("X-Tag-Me3", "3")
	req.Header.Set("X-Ignore-Me", "4")

	existingTags := []string{"first", "second"}
	existingTags = tagHeaders(req, map[string]interface{}{
		"x-tag-me":  0,
		"x-tag-me2": 0,
		"x-tag-me3": 0},
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
