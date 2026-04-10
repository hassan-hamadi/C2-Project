//go:build !linux

package funcs

import "fmt"

func registerUpdateDaemon(exePath string) error {
	return fmt.Errorf("update daemon is not supported on %s", "this OS")
}

func removeUpdateDaemon() error {
	return fmt.Errorf("update daemon is not supported on %s", "this OS")
}
