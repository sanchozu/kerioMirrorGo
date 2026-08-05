package handlers

import (
	"path/filepath"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	got, err := safeJoin(root, filepath.Join("v2", "repository", "file.gzip"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "v2", "repository", "file.gzip")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := safeJoin(root, filepath.Join("..", "outside")); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestCompareVersion(t *testing.T) {
	if compareVersion("9.4.2-100", "9.5.0-9017") >= 0 {
		t.Fatal("older version was not detected")
	}
	if compareVersion("9.5.0-9017", "9.5.0-9017") != 0 {
		t.Fatal("equal versions differ")
	}
	if compareVersion("9.5.1-1", "9.5.0-9017") <= 0 {
		t.Fatal("newer version was not detected")
	}
}

func TestParseKerioUpdate(t *testing.T) {
	version, link, err := parseKerioUpdate("0:5.123\nfull:https://example.test/ids_5_123.gz")
	if err != nil {
		t.Fatal(err)
	}
	if version != 123 || link != "https://example.test/ids_5_123.gz" {
		t.Fatalf("unexpected result: %d %q", version, link)
	}
}
