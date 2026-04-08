package funcs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const CommandTimeout = 120 * time.Second

// CurrentDir tracks the working directory across commands.
var CurrentDir string

func init() {
	dir, err := os.Getwd()
	if err != nil {
		dir, _ = os.UserHomeDir()
	}
	CurrentDir = dir
}

func IsCdCommand(command string) bool {
	trimmed := strings.TrimSpace(command)
	return trimmed == "cd" ||
		strings.HasPrefix(trimmed, "cd ") ||
		strings.HasPrefix(trimmed, "cd\t") ||
		strings.HasPrefix(trimmed, "cd\\") ||
		strings.HasPrefix(trimmed, "cd/")
}

func handleCd(command string) (string, error) {
	trimmed := strings.TrimSpace(command)
	args := strings.TrimPrefix(trimmed, "cd")
	args = strings.TrimSpace(args)

	if runtime.GOOS == "windows" {
		args = strings.TrimPrefix(args, "/d")
		args = strings.TrimPrefix(args, "/D")
		args = strings.TrimSpace(args)
	}

	if args == "" {
		return CurrentDir, nil
	}

	if args == "~" || strings.HasPrefix(args, "~/") || strings.HasPrefix(args, "~\\") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cd: cannot resolve home directory: %v", err)
		}
		args = home + args[1:]
	}

	var newDir string
	if filepath.IsAbs(args) {
		newDir = args
	} else {
		newDir = filepath.Join(CurrentDir, args)
	}

	newDir = filepath.Clean(newDir)

	info, err := os.Stat(newDir)
	if err != nil {
		return "", fmt.Errorf("cd: %s: no such directory", args)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("cd: %s: not a directory", args)
	}

	CurrentDir = newDir
	return CurrentDir, nil
}

func ExecuteCommand(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("empty command")
	}

	if IsCdCommand(command) {
		newDir, err := handleCd(command)
		if err != nil {
			return err.Error(), err
		}
		return newDir, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd.exe", "/C", command)
	default:
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}

	// Suppress the console window that Windows creates for CUI subprocesses.
	// The agent binary is built with -H=windowsgui so it has no console, but
	// each cmd.exe child would still flash a window without this flag.
	setHideWindow(cmd)

	cmd.Dir = CurrentDir

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output) + fmt.Sprintf("\n[TIMEOUT] Command killed after %s", CommandTimeout), fmt.Errorf("command timed out after %s", CommandTimeout)
	}

	if err != nil {
		return string(output) + "\n" + err.Error(), err
	}

	return string(output), nil
}
