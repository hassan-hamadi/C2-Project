//go:build !windows

package funcs

import "fmt"

func deleteWindowsRunValue(string) error {
	return fmt.Errorf("Windows registry is not supported on this OS")
}
