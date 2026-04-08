//go:build !windows

package funcs

import "os/exec"

// setHideWindow is a no-op on non-Windows platforms.
func setHideWindow(cmd *exec.Cmd) {}
