package signature_validator

import (
	"encoding/hex"
	"testing"
	"time"
)

const (
	token        = "5bcef48a3f03d311ff27d156630baf849e3b438b8a48fec99239d5c9"
	sharedSecret = "foobar"
	now          = 1546259837
)

func TestMasherySha256Sum_Hash(t *testing.T) {
	expected := "fce2e80253cd438b666341176f34bde499116b63719e2482dae6965518ffd316"

	hasher := MasherySha256Sum{}
	hashed := hex.EncodeToString(hasher.Hash(token, sharedSecret, now))

	if hashed != expected {
		t.Fatalf("expected %s, got %s", expected, hashed)
	}
}

func BenchmarkMasherySha256Sum_Hash(b *testing.B) {

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		hasher := MasherySha256Sum{}
		hasher.Hash(token, sharedSecret, time.Now().Unix())
	}
}
