package main

import (
	"testing"
)

func TestURLReplacer(t *testing.T) {

	config.AnalyticsConfig.NormaliseUrls.Enabled = true
	config.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
	config.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
	config.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}

	thisRecordUUID1 := AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
	thisRecordUUID2 := AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
	thisRecordUUID3 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	thisRecordUUID4 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	thisRecordID1 := AnalyticsRecord{Path: "/widgets/123456/getParams"}
	thisRecordCust := AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

	config.AnalyticsConfig.NormaliseUrls.compiledPatternSet = InitNormalisationPatterns()

	thisRecordUUID1.NormalisePath()
	thisRecordUUID2.NormalisePath()
	thisRecordUUID3.NormalisePath()
	thisRecordUUID4.NormalisePath()
	thisRecordID1.NormalisePath()
	thisRecordCust.NormalisePath()

	if thisRecordUUID1.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(thisRecordUUID1.Path)
		t.Error(config.AnalyticsConfig.NormaliseUrls)
	}

	if thisRecordUUID2.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(thisRecordUUID2.Path)
	}

	if thisRecordUUID3.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(thisRecordUUID3.Path)
	}

	if thisRecordUUID4.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(thisRecordUUID4.Path)
	}

	if thisRecordID1.Path != "/widgets/{id}/getParams" {
		t.Error("Path not altered, is:")
		t.Error(thisRecordID1.Path)
	}

	if thisRecordCust.Path != "/widgets/{id}/getParams/{var}" {
		t.Error("Path not altered, is:")
		t.Error(thisRecordCust.Path)
	}

}
