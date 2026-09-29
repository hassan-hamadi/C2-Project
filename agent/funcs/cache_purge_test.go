package funcs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configureCleanupTest(t *testing.T) {
	t.Helper()
	previousRemovePersistence := cleanupRemoveAutoUpdater
	previousExecutable := cleanupExecutable
	previousRemove := cleanupRemoveFile
	previousGOOS := cleanupRuntimeGOOS
	previousCreateTemp := cleanupCreateTemp
	previousStart := cleanupStartCommand
	t.Cleanup(func() {
		cleanupRemoveAutoUpdater = previousRemovePersistence
		cleanupExecutable = previousExecutable
		cleanupRemoveFile = previousRemove
		cleanupRuntimeGOOS = previousGOOS
		cleanupCreateTemp = previousCreateTemp
		cleanupStartCommand = previousStart
	})
}

func TestPurgeLocalInstallationFailsClosed(t *testing.T) {
	configureCleanupTest(t)
	removed := false
	cleanupExecutable = func() (string, error) { return "/tmp/agent", nil }
	cleanupRemoveFile = func(string) error { removed = true; return nil }
	cleanupRemoveAutoUpdater = func() error { return errors.New("persistence remains") }

	if _, err := PurgeLocalInstallation("/tmp/state"); err == nil {
		t.Fatal("persistence failure was reported as successful cleanup")
	}
	if removed {
		t.Fatal("binary removal ran after persistence removal failed")
	}

	cleanupRemoveAutoUpdater = func() error { return nil }
	cleanupRemoveFile = func(string) error { return errors.New("permission denied") }
	if _, err := PurgeLocalInstallation("/tmp/state"); err == nil {
		t.Fatal("binary removal failure was reported as successful cleanup")
	}
}

func TestPurgeLocalInstallationTreatsMissingBinaryAsSuccess(t *testing.T) {
	configureCleanupTest(t)
	cleanupRemoveAutoUpdater = func() error { return nil }
	cleanupExecutable = func() (string, error) { return "/tmp/already-gone", nil }
	cleanupRemoveFile = func(string) error { return os.ErrNotExist }
	cleanupRuntimeGOOS = "linux"

	deferred, err := PurgeLocalInstallation("/tmp/state")
	if err != nil || deferred {
		t.Fatalf("missing binary cleanup = deferred:%v err:%v", deferred, err)
	}
}

func TestWindowsCleanupHelperDeletesBinaryBeforeDurableMarker(t *testing.T) {
	configureCleanupTest(t)
	tempDir := t.TempDir()
	cleanupRemoveAutoUpdater = func() error { return nil }
	cleanupExecutable = func() (string, error) { return `C:\Program Files\Agent %name%^&\agent.exe`, nil }
	cleanupRuntimeGOOS = "windows"
	cleanupCreateTemp = func(dir string, pattern string) (*os.File, error) {
		if dir != filepath.Dir(`C:/Users/Name With Space/state%id%`) {
			t.Fatalf("helper directory = %q", dir)
		}
		return os.CreateTemp(tempDir, pattern)
	}
	var helperPath string
	var command []string
	cleanupStartCommand = func(name string, args ...string) error {
		command = append([]string{name}, args...)
		helperPath = args[len(args)-1]
		return nil
	}

	deferred, err := PurgeLocalInstallation(`C:/Users/Name With Space/state%id%`)
	if err != nil || !deferred {
		t.Fatalf("windows cleanup = deferred:%v err:%v", deferred, err)
	}
	if len(command) < 6 || command[0] != "cmd.exe" || command[3] != "" || command[4] != "/min" {
		t.Fatalf("cleanup command = %#v", command)
	}
	scriptBytes, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)
	if !strings.Contains(script, "%%name%%") || !strings.Contains(script, "%%id%%") ||
		!strings.Contains(script, "^^&") {
		t.Fatalf("batch metacharacters were not escaped: %s", script)
	}
	binaryDelete := strings.Index(script, ":delete_binary")
	stateDelete := strings.Index(script, ":delete_state")
	if binaryDelete < 0 || stateDelete <= binaryDelete || !strings.Contains(script, ".*\"") {
		t.Fatalf("cleanup ordering or marker glob missing: %s", script)
	}
	if info, err := os.Stat(helperPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("helper permissions = %v, %v", info, err)
	}
}

func TestWindowsCleanupLaunchFailureRemovesHelper(t *testing.T) {
	configureCleanupTest(t)
	tempDir := t.TempDir()
	cleanupRemoveAutoUpdater = func() error { return nil }
	cleanupExecutable = func() (string, error) { return `C:\agent.exe`, nil }
	cleanupRuntimeGOOS = "windows"
	cleanupCreateTemp = func(_ string, pattern string) (*os.File, error) {
		return os.CreateTemp(tempDir, pattern)
	}
	var helperPath string
	cleanupStartCommand = func(_ string, args ...string) error {
		helperPath = args[len(args)-1]
		return errors.New("start failed")
	}

	if _, err := PurgeLocalInstallation(`C:\state`); err == nil {
		t.Fatal("helper launch failure was reported as success")
	}
	if _, err := os.Stat(helperPath); !os.IsNotExist(err) {
		t.Fatalf("failed helper was not removed: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(tempDir, "endpoint-cleanup-*.bat")); len(matches) != 0 {
		t.Fatalf("cleanup helper leak: %v", matches)
	}
}
