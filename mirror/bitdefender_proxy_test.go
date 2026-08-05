package mirror

import (
	"strings"
	"testing"
)

func TestShouldCache(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		{
			name:     "versions.id should not be cached",
			filePath: "/av64bit/versions.id",
			expected: false,
		},
		{
			name:     "version.txt should not be cached",
			filePath: "/av64bit/version.txt",
			expected: false,
		},
		{
			name:     "cumulative.txt should not be cached",
			filePath: "/av64bit/cumulative.txt",
			expected: false,
		},
		{
			name:     "VERSIONS.ID (uppercase) should not be cached",
			filePath: "/av64bit/VERSIONS.ID",
			expected: false,
		},
		{
			name:     "versions.dat.gz should be cached",
			filePath: "/av64bit/versions.dat.gz",
			expected: true,
		},
		{
			name:     "update.dat should be cached",
			filePath: "/av64bit/update.dat",
			expected: true,
		},
		{
			name:     "some.cvd should be cached",
			filePath: "/av64bit/some.cvd",
			expected: true,
		},
		{
			name:     "double slash path versions.id",
			filePath: "//av64bit/versions.id",
			expected: false,
		},
		{
			name:     "nested path versions.id",
			filePath: "/av64bit/nested/versions.id",
			expected: false,
		},
		{
			name:     "just filename versions.id",
			filePath: "versions.id",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldCache(tt.filePath)
			if result != tt.expected {
				t.Errorf("shouldCache(%q) = %v, want %v", tt.filePath, result, tt.expected)
			}
		})
	}
}

func TestNonCacheableFilesList(t *testing.T) {
	// Verify the non-cacheable files list is not empty
	if len(nonCacheableFiles) == 0 {
		t.Error("nonCacheableFiles list should not be empty")
	}

	// Verify key files are in the list
	expectedFiles := []string{"versions.id", "version.txt", "cumulative.txt"}
	for _, expected := range expectedFiles {
		found := false
		for _, file := range nonCacheableFiles {
			if file == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file '%s' not found in nonCacheableFiles list", expected)
		}
	}
}

func BenchmarkShouldCache(b *testing.B) {
	paths := []string{
		"/av64bit/versions.id",
		"/av64bit/update.dat",
		"//av64bit/versions.id",
		"/av64bit/nested/path/file.cvd",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shouldCache(paths[i%len(paths)])
	}
}

func TestPatchBitdefenderVersions(t *testing.T) {
	in := []byte("+ 2aea119dd74349d432b4f2c9b0bae125 bdcore.dll 73716\n" +
		"0 0ba21fbc4e1ccbb0942261c18e317de7 bdcore.so.freebsd11-x86_64 18855\n" +
		"0 e3c1cf2bbc5cd280bcb0d82459ea9bc5 bdcore.so.linux-x86_64 17905\n" +
		"0 c7eafab33bc845099e873a90229741c8 bdcore.so.macosx-x86_64 23668\n" +
		"1 11111111111111111111111111111111 plugins.dat 999\n")
	out := string(PatchBitdefenderVersions(in))

	if !strings.Contains(out, "e3c1cf2bbc5cd280bcb0d82459ea9bc5 bdcore.dll 17905") {
		t.Errorf("bdcore.dll entry not patched to linux engine md5/size:\n%s", out)
	}
	if !strings.Contains(out, "e3c1cf2bbc5cd280bcb0d82459ea9bc5 bdcore.so.linux-x86_64 17905") {
		t.Errorf("linux engine entry changed unexpectedly:\n%s", out)
	}
	if !strings.Contains(out, "11111111111111111111111111111111 plugins.dat 999") {
		t.Errorf("unrelated line changed:\n%s", out)
	}

	if got := string(PatchBitdefenderVersions([]byte("+ 2aea... bdcore.dll 73716\n"))); got != "+ 2aea... bdcore.dll 73716\n" {
		t.Errorf("data without linux engine entry should be unchanged, got:\n%s", got)
	}
}
