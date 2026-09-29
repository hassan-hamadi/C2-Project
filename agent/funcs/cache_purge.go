package funcs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var cleanupRemoveAutoUpdater = RemoveAutoUpdater
var cleanupExecutable = os.Executable
var cleanupRemoveFile = os.Remove
var cleanupRuntimeGOOS = runtime.GOOS
var cleanupCreateTemp = os.CreateTemp
var cleanupStartCommand = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	setHideWindow(cmd)
	return cmd.Start()
}

// PurgeLocalInstallation removes persistence and then removes the running
// executable. A true deferred result means a Windows helper owns executable
// and durable-state deletion and the caller may exit. On other platforms the
// executable has already been unlinked when this returns successfully.
func PurgeLocalInstallation(stateBase string) (deferred bool, err error) {
	if stateBase == "" {
		return false, fmt.Errorf("cleanup state path is empty")
	}
	if err := cleanupRemoveAutoUpdater(); err != nil {
		return false, fmt.Errorf("remove persistence: %w", err)
	}

	exePath, err := cleanupExecutable()
	if err != nil {
		return false, fmt.Errorf("locate executable: %w", err)
	}

	if cleanupRuntimeGOOS == "windows" {
		if err := scheduleWindowsCleanup(exePath, stateBase); err != nil {
			return false, err
		}
		return true, nil
	}

	if err := cleanupRemoveFile(exePath); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("remove executable: %w", err)
	}
	return false, nil
}

func scheduleWindowsCleanup(exePath, stateBase string) error {
	exeArg, err := escapeBatchPath(exePath)
	if err != nil {
		return fmt.Errorf("prepare executable cleanup path: %w", err)
	}
	stateArg, err := escapeBatchPath(stateBase)
	if err != nil {
		return fmt.Errorf("prepare state cleanup path: %w", err)
	}

	output, err := cleanupCreateTemp(filepath.Dir(stateBase), "endpoint-cleanup-*.bat")
	if err != nil {
		return fmt.Errorf("create cleanup helper: %w", err)
	}
	helperPath := output.Name()
	complete := false
	defer func() {
		_ = output.Close()
		if !complete {
			_ = os.Remove(helperPath)
		}
	}()
	if err := output.Chmod(0600); err != nil {
		return fmt.Errorf("protect cleanup helper: %w", err)
	}

	script := windowsCleanupScript(exeArg, stateArg)
	if _, err := output.WriteString(script); err != nil {
		return fmt.Errorf("write cleanup helper: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync cleanup helper: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close cleanup helper: %w", err)
	}

	if err := cleanupStartCommand("cmd.exe", "/C", "start", "", "/min", helperPath); err != nil {
		return fmt.Errorf("start cleanup helper: %w", err)
	}
	complete = true
	return nil
}

func escapeBatchPath(path string) (string, error) {
	if path == "" || strings.ContainsAny(path, "\x00\r\n\"") {
		return "", fmt.Errorf("path cannot be represented safely in a batch file")
	}
	path = strings.ReplaceAll(path, "^", "^^")
	path = strings.ReplaceAll(path, "%", "%%")
	return path, nil
}

func windowsCleanupScript(exePath, stateBase string) string {
	return "@echo off\r\n" +
		"setlocal DisableDelayedExpansion\r\n" +
		":delete_binary\r\n" +
		"timeout /t 2 /nobreak >nul\r\n" +
		"del /f /q \"" + exePath + "\" >nul 2>&1\r\n" +
		"if exist \"" + exePath + "\" goto delete_binary\r\n" +
		":delete_state\r\n" +
		"del /f /q \"" + stateBase + ".*\" >nul 2>&1\r\n" +
		"if exist \"" + stateBase + ".*\" (\r\n" +
		"  timeout /t 2 /nobreak >nul\r\n" +
		"  goto delete_state\r\n" +
		")\r\n" +
		"del /f /q \"%~f0\"\r\n"
}
