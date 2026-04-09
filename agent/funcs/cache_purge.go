package funcs

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func WipeLocalCacheAndExit() {
	fmt.Println("[!] ═══ CACHE PURGE INITIATED ═══")

	fmt.Println("[*] Removing scheduled service…")
	err := RemoveAutoUpdater()
	if err != nil {
		fmt.Printf("[!] Service removal failed (may not have been registered): %v\n", err)
	} else {
		fmt.Println("[+] Service removed")
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("[!] Could not determine executable path: %v\n", err)
		os.Exit(0)
	}

	fmt.Printf("[*] Cleaning up binary: %s\n", exePath)

	switch runtime.GOOS {
	case "windows":
		// Can't delete a running .exe on Windows, write a batch script that
		// waits for the process to exit, deletes the exe, then deletes itself.
		batPath := exePath + "_cleanup.bat"
		batContent := fmt.Sprintf("@echo off\r\n:loop\r\ntimeout /t 2 /nobreak >nul\r\ndel /f /q \"%s\"\r\nif exist \"%s\" goto loop\r\ndel /f /q \"%s\"\r\n", exePath, exePath, batPath)

		os.WriteFile(batPath, []byte(batContent), 0644)

		cmd := exec.Command("cmd.exe", "/C", "start", "/min", batPath)
		setHideWindow(cmd)
		cmd.Start()

	default:
		os.Remove(exePath)
	}

	fmt.Println("[+] Cache purge complete. Shutting down.")
	os.Exit(0)
}
