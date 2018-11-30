package regexp

import (
	"fmt"
	"testing"
)

var tStr1 = "aαa⏰𐌈"
var tStr2 = "bβb⏳𐌏"

func TestKeyImmutabilityReset(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString(tStr1)
	k := kb.Key()

	kb.Reset()
	if k != tStr1 {
		t.Errorf("key should remains %v, got %v", tStr1, k)
	}
}

func TestKeyImmutabilityChangeBuilderState(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString(tStr1)
	k := kb.Key()

	kb.AppendString(tStr2)
	if k != tStr1 {
		t.Errorf("key should remains %v, got %v", tStr1, k)
	}
}

func TestAppendString(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString(tStr1).AppendString(tStr2)
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	exp := tStr1 + tStr2
	if key != exp || nsKey != exp {
		t.Errorf("expect to got %v, got %v and %v", exp, key, nsKey)
	}
}

func TestAppendBytes(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString(tStr1).AppendBytes([]byte(tStr2))
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	exp := tStr1 + tStr2
	if key != exp || nsKey != exp {
		t.Errorf("expect to got %v, got %v and %v", exp, key, nsKey)
	}
}

func TestAppendInt(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString(tStr1).AppendInt(123)
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	exp := tStr1 + "123"
	if key != exp || nsKey != exp {
		t.Errorf("expect to got %v, got %v and %v", exp, key, nsKey)
	}
}

func TestWrite(t *testing.T) {
	kb := keyBuilder{}

	b := []byte(tStr2)
	n, err := kb.AppendString(tStr1).Write(b)

	if err != nil {
		t.Errorf("Write should always pass without error, got %v", err)
	}

	if n != len(b) {
		t.Errorf("Write should always return length of byte slice argument. Expected %v, got %v", len(b), n)
	}

	nsKey := kb.UnsafeKey()
	key := kb.Key()

	exp := tStr1 + tStr2
	if key != exp || nsKey != exp {
		t.Errorf("expect to got %v, got %v and %v", exp, key, nsKey)
	}
}

func TestAppendf(t *testing.T) {
	kb := keyBuilder{}

	f := func(s string) string { return s }

	kb.AppendString(tStr1).Appendf("%p", f)
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	exp := tStr1 + fmt.Sprintf("%p", f)
	if key != exp || nsKey != exp {
		t.Errorf("expect to got %v, got %v and %v", exp, key, nsKey)
	}
}
