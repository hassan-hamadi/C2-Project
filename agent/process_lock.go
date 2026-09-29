package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var errAgentAlreadyRunning = errors.New("another agent process already owns this state")

type heldProcessLock struct {
	file *os.File
	path string
}

var agentProcessLock = struct {
	sync.Mutex
	held *heldProcessLock
}{}

func processLockPath(stateBase string) string {
	return stateBase + ".lock"
}

// acquireAgentProcessLock prevents two processes launched from the same build
// and executable path from loading or replacing the same durable state.
func acquireAgentProcessLock() error {
	agentProcessLock.Lock()
	defer agentProcessLock.Unlock()
	if agentProcessLock.held != nil {
		return errAgentAlreadyRunning
	}

	stateBase, err := resultStateBasePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(stateBase)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state directory for process lock: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("protect state directory for process lock: %w", err)
	}

	path := processLockPath(stateBase)
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("process lock path is not a regular file")
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect process lock: %w", statErr)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open process lock: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("protect process lock: %w", err)
	}

	acquired, err := tryLockProcessFile(file)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("acquire process lock: %w", err)
	}
	if !acquired {
		_ = file.Close()
		return errAgentAlreadyRunning
	}
	agentProcessLock.held = &heldProcessLock{file: file, path: path}
	return nil
}

// releaseAgentProcessLock releases this process's OS lock. When remove is true,
// the empty lock file is unlinked before releasing ownership; callers only use
// that mode after the executable has been removed during Unix self-destruct.
func releaseAgentProcessLock(remove bool) error {
	agentProcessLock.Lock()
	defer agentProcessLock.Unlock()
	held := agentProcessLock.held
	if held == nil {
		return nil
	}
	if remove {
		if err := os.Remove(held.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove process lock: %w", err)
		}
	}

	unlockErr := unlockProcessFile(held.file)
	closeErr := held.file.Close()
	agentProcessLock.held = nil
	return errors.Join(unlockErr, closeErr)
}
