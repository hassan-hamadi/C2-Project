package funcs

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWorkingDirectoryChangeFailsClosed(t *testing.T) {
	original := getCurrentDir()
	t.Cleanup(func() {
		if _, err := updateWorkingContext("cd " + original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	first, next := t.TempDir(), t.TempDir()
	if _, err := updateWorkingContext("cd " + first); err != nil {
		t.Fatal(err)
	}

	var releases []func()
	for range 2 {
		release, err := HoldWorkingDirectory()
		if err != nil {
			t.Fatal(err)
		}
		release = sync.OnceFunc(release)
		t.Cleanup(release)
		releases = append(releases, release)
	}
	releases[0]()
	if _, err := updateWorkingContext("cd " + next); err == nil || !strings.Contains(err.Error(), "another task is active") {
		t.Fatalf("expected busy error with one task still active, got %v", err)
	}
	if got := getCurrentDir(); got != first {
		t.Fatalf("earlier task's directory changed from %q to %q", first, got)
	}
	releases[1]()
	if got, err := updateWorkingContext("cd"); err != nil || got != first {
		t.Fatalf("directory query = %q, %v; want %q", got, err, first)
	}
	if release, err := HoldWorkingDirectory(); err == nil {
		release()
		t.Fatal("accepted a new task after a rejected directory change")
	}
	if _, err := updateWorkingContext("cd " + next); err != nil {
		t.Fatal(err)
	}
	release, err := HoldWorkingDirectory()
	if err != nil {
		t.Fatal(err)
	}
	release()
	if got := getCurrentDir(); got != next {
		t.Fatalf("new task's directory = %q, want %q", got, next)
	}
	if _, err := updateWorkingContext("cd " + filepath.Join(next, "missing")); err == nil {
		t.Fatal("accepted a nonexistent working directory")
	}
	if release, err := HoldWorkingDirectory(); err == nil {
		release()
		t.Fatal("accepted a new task after a failed directory change")
	}
}
