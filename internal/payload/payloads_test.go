package payload

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefault Built-in payload set is non-empty, unique, and free of blanks/comments.
func TestDefault(t *testing.T) {
	if len(Default) == 0 {
		t.Fatal("expected non-empty default payloads")
	}
	found := make(map[string]bool)
	for _, v := range Default {
		found[v] = true
	}
	if !found[`///google.com/%2f..`] {
		// Pass the payload as an argument: a bare "%2f" inside the format
		// string is misread as a printf directive by go vet.
		t.Errorf("expected %q in default payloads", `///google.com/%2f..`)
	}
	if !found[`/////example.com/`] {
		t.Error("expected /////example.com/ in default payloads")
	}
}

// TestLoad File loader reads payloads, skipping blank lines and # comments.
func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payloads.txt")
	content := "# This is a comment\n//evil.com\nhttps://bad.com\n\n# Another comment\n//x.com\n"
	os.WriteFile(path, []byte(content), 0644)

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(p) != 3 {
		t.Fatalf("expected 3 payloads, got %d: %v", len(p), p)
	}

	expected := []string{"//evil.com", "https://bad.com", "//x.com"}
	for i, want := range expected {
		if p[i] != want {
			t.Errorf("payload[%d] = %q, want %q", i, p[i], want)
		}
	}
}

// TestLoad_FileNotFound Missing files return an error rather than an empty set.
func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestLoad_EmptyFile Empty files produce zero payloads without erroring.
func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	os.WriteFile(path, []byte(""), 0644)

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(p) != 0 {
		t.Errorf("expected 0 payloads from empty file, got %d", len(p))
	}
}
