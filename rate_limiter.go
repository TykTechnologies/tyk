package main

import (
	"github.com/TykTechnologies/leakybucket"
	"github.com/TykTechnologies/leakybucket/memory"
)

var BucketStore leakybucket.Storage

func InitBucketStore() {
	BucketStore = memory.New()
}
