package funcs

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A child process confines the file-size limit and signal handling to this test.
func TestDownloadWriteFailurePreservesDestination(t *testing.T) {
	if os.Getenv("C2_TEST_DOWNLOAD_WRITE_LIMIT") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDownloadWriteFailurePreservesDestination$")
		cmd.Env = append(os.Environ(), "C2_TEST_DOWNLOAD_WRITE_LIMIT=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("write-failure child: %v\n%s", err, output)
		}
		return
	}

	dir := t.TempDir()
	destination := filepath.Join(dir, "document.txt")
	if err := os.WriteFile(destination, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 1024, Max: 1024}); err != nil {
		t.Fatal(err)
	}
	http.DefaultClient = &http.Client{Transport: downloadRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: 4096,
			Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 4096)))}, nil
	})}
	if _, err := FetchUpdatePackage("http://fixture.invalid/files/", "7", destination, "fixture", "secret", 42); err == nil {
		t.Fatal("write failure reported success")
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "original" {
		t.Fatalf("original destroyed after write failure: %q, %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file leaked: %v, %v", entries, err)
	}
}
