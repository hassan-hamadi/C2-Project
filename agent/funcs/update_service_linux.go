//go:build linux

package funcs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// registerUpdateDaemon creates a systemd user service that starts the
// agent on login. The unit file is written to ~/.config/systemd/user/
// and enabled via systemctl --user. No root required.
func registerUpdateDaemon(exePath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to determine home directory: %w", err)
	}

	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return fmt.Errorf("failed to create unit directory: %w", err)
	}

	unitName := ServiceLabel + ".service"
	unitPath := filepath.Join(unitDir, unitName)

	unitContent := fmt.Sprintf(`[Unit]
Description=Endpoint Telemetry Diagnostics Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
`, exePath)

	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("failed to write unit file: %w", err)
	}

	// Reload systemd so it picks up the new unit file.
	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload failed: %s - %w", string(out), err)
	}

	// Enable the service for auto-start on login.
	if out, err := exec.Command("systemctl", "--user", "enable", unitName).CombinedOutput(); err != nil {
		return fmt.Errorf("enable failed: %s - %w", string(out), err)
	}

	fmt.Printf("[+] Update daemon registered (systemd user service): %s\n", unitName)
	return nil
}

// removeUpdateDaemon disables and removes the systemd user service.
func removeUpdateDaemon() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to determine home directory: %w", err)
	}

	unitName := ServiceLabel + ".service"
	unitPath := filepath.Join(home, ".config", "systemd", "user", unitName)

	// Disable the service (ignore errors — may not be enabled).
	exec.Command("systemctl", "--user", "disable", unitName).CombinedOutput()

	// Stop the service (ignore errors — may not be running).
	exec.Command("systemctl", "--user", "stop", unitName).CombinedOutput()

	// Remove the unit file.
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unit file: %w", err)
	}

	// Reload so systemd forgets about the unit.
	exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput()

	fmt.Printf("[-] Update daemon removed (systemd user service): %s\n", unitName)
	return nil
}
