package blob

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestPutDeduplicatesAndGCs(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash1, size, err := store.Put(bytes.NewBufferString("sample"), 16)
	if err != nil || size != 6 {
		t.Fatalf("Put() = %q, %d, %v", hash1, size, err)
	}
	hash2, _, err := store.Put(bytes.NewBufferString("sample"), 16)
	if err != nil || hash1 != hash2 {
		t.Fatalf("deduplication failed: %q != %q (%v)", hash1, hash2, err)
	}
	if err := store.GC(context.Background(), map[string]struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Path(hash1)); !os.IsNotExist(err) {
		t.Fatalf("blob was not removed: %v", err)
	}
}

func TestPutRejectsOversize(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Put(bytes.NewBufferString("too large"), 3); err == nil {
		t.Fatal("expected upload limit error")
	}
}
