package funcs

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type downloadRoundTripper func(*http.Request) (*http.Response, error)

func (f downloadRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type interruptedDownload struct{ sent bool }

type checkedDownload struct {
	reader io.Reader
	check  func()
}

func (r checkedDownload) Read(p []byte) (int, error) {
	r.check()
	return r.reader.Read(p)
}

func (r *interruptedDownload) Read(p []byte) (int, error) {
	if r.sent {
		return 0, errors.New("interrupted response")
	}
	r.sent = true
	return copy(p, "partial"), nil
}

func TestDownloadFailurePreservesDestination(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, shortBody := range []bool{false, true} {
			t.Run(fmt.Sprintf("existing=%v/short=%v", existing, shortBody), func(t *testing.T) {
				dir := t.TempDir()
				destination := filepath.Join(dir, "document.txt")
				if existing {
					if err := os.WriteFile(destination, []byte("original content"), 0640); err != nil {
						t.Fatal(err)
					}
				}
				previous := http.DefaultClient
				t.Cleanup(func() { http.DefaultClient = previous })
				var body io.Reader = &interruptedDownload{}
				length := int64(-1)
				if shortBody {
					body = strings.NewReader("short")
					length = 100
				}
				http.DefaultClient = &http.Client{Transport: downloadRoundTripper(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(body), ContentLength: length}, nil
				})}
				if _, err := FetchUpdatePackage("http://fixture.invalid/files/", "7", destination, "fixture", "secret", 42); err == nil {
					t.Fatal("incomplete download reported success")
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if existing {
					got, _ := os.ReadFile(destination)
					if string(got) != "original content" || len(entries) != 1 {
						t.Fatalf("old content changed or temp leaked: %q, %v", got, entries)
					}
				} else if len(entries) != 0 {
					t.Fatalf("failed download left files: %v", entries)
				}
			})
		}
	}
}

func TestDownloadPublishesOnlyCompleteFileAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "document.txt")
	if err := os.WriteFile(destination, []byte("original"), 0640); err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previous })
	http.DefaultClient = &http.Client{Transport: downloadRoundTripper(func(*http.Request) (*http.Response, error) {
		body := checkedDownload{reader: strings.NewReader("complete replacement"), check: func() {
			got, err := os.ReadFile(destination)
			if err != nil || string(got) != "original" {
				t.Fatalf("destination changed before completion: %q, %v", got, err)
			}
		}}
		return &http.Response{StatusCode: 200, ContentLength: 20, Body: io.NopCloser(body)}, nil
	})}
	if _, err := FetchUpdatePackage("http://fixture.invalid/files/", "7", destination, "fixture", "secret", 42); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "complete replacement" {
		t.Fatalf("unexpected destination: %q, %v", got, err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("permissions changed: %v", info.Mode())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v", entries)
	}
}

func TestDownloadRejectsSymlinkAndKeepsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, destination); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	previous := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previous })
	http.DefaultClient = &http.Client{Transport: downloadRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: 3, Body: io.NopCloser(strings.NewReader("new"))}, nil
	})}
	if _, err := FetchUpdatePackage("http://fixture.invalid/files/", "7", destination, "fixture", "secret", 42); err == nil {
		t.Fatal("symlink was accepted")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatalf("symlink target changed: %q", got)
	}
	if _, err := os.Readlink(destination); err != nil {
		t.Fatal("symlink was replaced")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("temporary files leaked: %v", entries)
	}
}

func TestFetchUpdatePackageSendsAgentAssignment(t *testing.T) {
	const secret = "1111111111111111111111111111111111111111111111111111111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/files/7" ||
			r.Header.Get("X-Agent-ID") != "agent-a" ||
			r.Header.Get("X-Task-ID") != "42" ||
			r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "missing assignment credentials", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("staged content"))
	}))
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "stage.bin")
	if _, err := FetchUpdatePackage(server.URL+"/files/", "7", destination, "agent-a", secret, 42); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "staged content" {
		t.Fatalf("downloaded %q, want staged content", got)
	}
}
