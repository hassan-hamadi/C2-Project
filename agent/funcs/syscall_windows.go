//go:build windows

package funcs

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW prevents the OS from allocating a console for the child process.
const createNoWindow = 0x08000000

// setHideWindow suppresses any console window that Windows would normally
// create when spawning a CUI subprocess (e.g. cmd.exe). Without this,
// even a windowless parent process causes a brief console flash per command.
func setHideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
