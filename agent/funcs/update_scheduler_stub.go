//go:build !windows

package funcs

import "fmt"

func registerUpdateSchedule(exePath string) error {
	return fmt.Errorf("update scheduler is not supported on %s", "this OS")
}

func removeUpdateSchedule() error {
	return fmt.Errorf("update scheduler is not supported on %s", "this OS")
}
