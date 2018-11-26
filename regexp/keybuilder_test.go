package regexp

import (
	"fmt"
	"testing"
)

func TestKeyImmutabilityReset(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString("aaa")
	k := kb.Key()

	kb.Reset()
	if k != "aaa" {
		t.Errorf("key should remains aaa, got %v", k)
	}
}

func TestKeyImmutabilityChangeBuilderState(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString("aaa")
	k := kb.Key()

	kb.AppendString("bbb")
	if k != "aaa" {
		t.Errorf("key should remains aaa, got %v", k)
	}
}

func TestAppendString(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString("aaa").AppendString("bbb")
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	if key != "aaabbb" || nsKey != "aaabbb" {
		t.Errorf("expect to got aaabbb, got %v and %v", key, nsKey)
	}
}

func TestAppendBytes(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString("aaa").AppendBytes([]byte("bbb"))
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	if key != "aaabbb" || nsKey != "aaabbb" {
		t.Errorf("expect to got aaabbb, got %v and %v", key, nsKey)
	}
}

func TestAppendInt(t *testing.T) {
	kb := keyBuilder{}

	kb.AppendString("aaa").AppendInt(123)
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	if key != "aaa123" || nsKey != "aaa123" {
		t.Errorf("expect to got aaa123, got %v and %v", key, nsKey)
	}
}

func TestWrite(t *testing.T) {
	kb := keyBuilder{}

	b := []byte("bbb")
	n, err := kb.AppendString("aaa").Write(b)

	if err != nil {
		t.Errorf("Write should always pass without error, got %v", err)
	}

	if n != len(b) {
		t.Errorf("Write should always return length of byte slice argument. Expected %v, got %v", len(b), n)
	}

	nsKey := kb.UnsafeKey()
	key := kb.Key()

	if key != "aaabbb" || nsKey != "aaabbb" {
		t.Errorf("expect to got aaabbb, got %v and %v", key, nsKey)
	}
}

func TestAppendf(t *testing.T) {
	kb := keyBuilder{}

	f := func(s string) string { return s }
	expected := fmt.Sprintf("aaa%p", f)

	kb.AppendString("aaa").Appendf("%p", f)
	nsKey := kb.UnsafeKey()
	key := kb.Key()

	if key != expected || nsKey != expected {
		t.Errorf("expect to got %v, got %v and %v", expected, key, nsKey)
	}
}
