package storage

import (
	"fmt"
	"github.com/satori/go.uuid"
	"testing"
)

func TestBuildRange(t *testing.T) {
	for i, v := range HashRange {
		if len(v) != 3 {
			fmt.Printf("Val is: %s (index: %v) len is: %v \n", v, i, len(v))
			t.Fatal("len is not 3")
		}
	}
}

func TestAppendCollision(t *testing.T) {
	testRange := []string{
		"111",
		"112",
		"113",
		"55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a80",
		"55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a801",
		"55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a8012",
		"55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a80123",
		"55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a801234",
	}
	seen := make([]string, len(testRange))

	for i := range testRange {
		testRange[i] = uuid.NewV4().String()
	}

	var h string
	for i, v := range testRange {
		h = HashMM2(v)
		if stringInSlice(h, seen) {
			t.Fatal("collison detected with incremental key")
		}
		seen[i] = v
	}
}

func TestTypeSplit(t *testing.T) {
	mm3Key := "55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a80"
	custKey := "customKey123"
	mm2Key := "55d5927329415b000100003bb0da4dcb354947eca50a995e8b7d1a80xa7"

	mm3Hash := HashStr(mm3Key)
	custHash := HashStr(custKey)
	m2Hash := HashStr(mm2Key)

	if mm3Hash != "de6a0f23" {
		t.Fatalf("incorrect MM3 hash, got %v", mm3Hash)
	}

	if custHash != "c6e73d88" {
		t.Fatal("incorrect cust hash")
	}

	if m2Hash != "b187d7ca9320499" {
		t.Fatal("incorrect MM2 hash")
	}

}

func checkMM2Collisions(t *testing.T) {
	testRange := make([]string, 50000)
	seen := make([]string, 50000)

	for i := range testRange {
		testRange[i] = uuid.NewV4().String()
	}

	fmt.Println(testRange[:5])

	collisions := 0
	var h string
	for i, v := range testRange {
		h = HashMM2(v)
		if stringInSlice(h, seen) {
			collisions += 1
		}
		seen[i] = v

		if i < 10 {
			fmt.Println(h)
		}
	}
}
