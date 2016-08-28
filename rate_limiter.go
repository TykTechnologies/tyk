package main

import (
	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memorycache"
)

var BucketStore leakybucket.Storage

func InitBucketStore() {
	BucketStore = memorycache.New()
}
