package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"endpoint-telemetry/funcs"
)

// Each update is written as a new encrypted generation before older
// generations are removed, avoiding a truncate/replace window.
var resultOutbox = struct {
	sync.Mutex
	pending        map[int]pendingResult
	cleanupPending bool
	initialized    bool
	sequence       uint64
}{pending: make(map[int]pendingResult)}

type pendingResult struct {
	Output   string `json:"output"`
	Flush    bool   `json:"flush"`
	ReportID string `json:"report_id"`
}

type durableResultState struct {
	Version        int                   `json:"version"`
	Sequence       uint64                `json:"sequence"`
	KeyID          string                `json:"key_id"`
	EndpointID     string                `json:"agent_id"`
	AgentSecret    string                `json:"agent_secret"`
	Pending        map[int]pendingResult `json:"pending"`
	CleanupPending bool                  `json:"cleanup_pending"`
}

var sendDiagnosticResult = SubmitDiagnosticReport
var purgeLocalInstallation = funcs.PurgeLocalInstallation
var exitProcess = os.Exit
var cleanupSleep = time.Sleep
var resultStatePathOverride string

// errAgentIdentityGone means the server no longer recognizes this agent
// (force-deleted or tombstone already purged). Flush may treat this as success.
type errAgentIdentityGone struct {
	StatusCode int
	Body       string
}

func (e *errAgentIdentityGone) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Body)
}

func isAgentIdentityGone(err error) bool {
	var gone *errAgentIdentityGone
	return errors.As(err, &gone)
}

func resultStateBasePath() (string, error) {
	if resultStatePathOverride != "" {
		return resultStatePathOverride, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config directory: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	digest := sha256.Sum256([]byte(KeyID + "\x00" + executable))
	return filepath.Join(dir, "endpoint-telemetry", "result-state-"+hex.EncodeToString(digest[:8])), nil
}

func validateDurableState(state durableResultState) error {
	if state.Version != 1 || state.KeyID != KeyID || state.EndpointID == "" {
		return errors.New("state identity does not match this build")
	}
	secret, err := hex.DecodeString(state.AgentSecret)
	if err != nil || len(secret) != 32 || hex.EncodeToString(secret) != state.AgentSecret {
		return errors.New("state contains an invalid agent secret")
	}
	for id, result := range state.Pending {
		if id < 1 {
			return errors.New("state contains an invalid task ID")
		}
		if result.ReportID != "" {
			reportID, err := hex.DecodeString(result.ReportID)
			if err != nil || len(reportID) != 32 || hex.EncodeToString(reportID) != result.ReportID {
				return errors.New("state contains an invalid report ID")
			}
		}
	}
	return nil
}

func newReportID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate report ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func durableStateFiles(base string) ([]string, error) {
	matches, err := filepath.Glob(base + ".*")
	if err != nil {
		return nil, err
	}
	files := matches[:0]
	for _, path := range matches {
		if path == processLockPath(base) {
			continue
		}
		info, statErr := os.Lstat(path)
		if statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			files = append(files, path)
		}
	}
	return files, nil
}

func loadDurableStateLocked(base string) (*durableResultState, error) {
	files, err := durableStateFiles(base)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, os.ErrNotExist
	}
	var valid []durableResultState
	for _, path := range files {
		encoded, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		plain, openErr := funcs.UnsealTelemetry(EncryptionKey, string(encoded))
		if openErr != nil {
			continue
		}
		var state durableResultState
		if json.Unmarshal(plain, &state) != nil || validateDurableState(state) != nil {
			continue
		}
		if state.Pending == nil {
			state.Pending = make(map[int]pendingResult)
		}
		valid = append(valid, state)
	}
	if len(valid) == 0 {
		return nil, errors.New("durable result state exists but cannot be authenticated")
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Sequence > valid[j].Sequence })
	return &valid[0], nil
}

func persistDurableStateLocked() error {
	base, err := resultStateBasePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(base)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}

	resultOutbox.sequence++
	state := durableResultState{
		Version: 1, Sequence: resultOutbox.sequence, KeyID: KeyID,
		EndpointID: EndpointID, AgentSecret: AgentSecret, Pending: resultOutbox.pending,
		CleanupPending: resultOutbox.cleanupPending,
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode durable result state: %w", err)
	}
	encoded, err := funcs.SealTelemetry(EncryptionKey, plain)
	if err != nil {
		return fmt.Errorf("encrypt durable result state: %w", err)
	}

	output, err := os.CreateTemp(dir, filepath.Base(base)+".")
	if err != nil {
		return fmt.Errorf("create state generation: %w", err)
	}
	path := output.Name()
	complete := false
	defer func() {
		_ = output.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := output.Chmod(0600); err != nil {
		return err
	}
	if _, err := output.WriteString(encoded); err != nil {
		return fmt.Errorf("write durable result state: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync durable result state: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close durable result state: %w", err)
	}
	complete = true

	files, _ := durableStateFiles(base)
	for _, old := range files {
		if old != path {
			_ = os.Remove(old)
		}
	}
	if directory, openErr := os.Open(dir); openErr == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func initializeDurableResultState() error {
	resultOutbox.Lock()
	defer resultOutbox.Unlock()
	if resultOutbox.initialized {
		return nil
	}
	base, err := resultStateBasePath()
	if err != nil {
		return err
	}
	state, err := loadDurableStateLocked(base)
	if err != nil {
		files, listErr := durableStateFiles(base)
		if listErr != nil {
			return listErr
		}
		if len(files) != 0 {
			return err
		}
		resultOutbox.pending = make(map[int]pendingResult)
		resultOutbox.cleanupPending = false
		resultOutbox.sequence = 0
		if err := persistDurableStateLocked(); err != nil {
			return err
		}
	} else {
		EndpointID = state.EndpointID
		AgentSecret = state.AgentSecret
		resultOutbox.pending = state.Pending
		resultOutbox.cleanupPending = state.CleanupPending
		resultOutbox.sequence = state.Sequence
		migrated := false
		for id, result := range resultOutbox.pending {
			if result.ReportID != "" {
				continue
			}
			reportID, reportErr := newReportID()
			if reportErr != nil {
				return reportErr
			}
			result.ReportID = reportID
			resultOutbox.pending[id] = result
			migrated = true
		}
		if migrated {
			if err := persistDurableStateLocked(); err != nil {
				return fmt.Errorf("migrate durable result acknowledgements: %w", err)
			}
		}
	}
	resultOutbox.initialized = true
	return nil
}

func rememberPendingResult(jobID int, result pendingResult) error {
	resultOutbox.Lock()
	defer resultOutbox.Unlock()
	if resultOutbox.cleanupPending {
		return errors.New("local cleanup is pending")
	}
	resultOutbox.pending[jobID] = result
	return persistDurableStateLocked()
}

func markCleanupPending(jobID int, expected pendingResult) error {
	resultOutbox.Lock()
	defer resultOutbox.Unlock()
	current, ok := resultOutbox.pending[jobID]
	if !ok || current != expected {
		return errors.New("flush result is no longer pending")
	}
	delete(resultOutbox.pending, jobID)
	previousCleanup := resultOutbox.cleanupPending
	resultOutbox.cleanupPending = true
	if err := persistDurableStateLocked(); err != nil {
		resultOutbox.pending[jobID] = current
		resultOutbox.cleanupPending = previousCleanup
		return err
	}
	return nil
}

func cleanupIsPending() bool {
	resultOutbox.Lock()
	defer resultOutbox.Unlock()
	return resultOutbox.cleanupPending
}

func acknowledgePendingResult(jobID int, expected pendingResult) error {
	resultOutbox.Lock()
	defer resultOutbox.Unlock()
	current, ok := resultOutbox.pending[jobID]
	if !ok || current != expected {
		return nil
	}
	delete(resultOutbox.pending, jobID)
	if err := persistDurableStateLocked(); err != nil {
		resultOutbox.pending[jobID] = current
		return err
	}
	return nil
}

func clearDurableResultState() error {
	resultOutbox.Lock()
	defer resultOutbox.Unlock()
	base, err := resultStateBasePath()
	if err != nil {
		return err
	}
	files, err := durableStateFiles(base)
	if err != nil {
		return err
	}
	for _, path := range files {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	resultOutbox.pending = make(map[int]pendingResult)
	resultOutbox.cleanupPending = false
	return nil
}

func attemptPendingCleanup() (bool, error) {
	if !cleanupIsPending() {
		return false, nil
	}
	base, err := resultStateBasePath()
	if err != nil {
		return true, err
	}
	deferred, err := purgeLocalInstallation(base)
	if err != nil {
		return true, err
	}
	if !deferred {
		if err := releaseAgentProcessLock(true); err != nil {
			return true, fmt.Errorf("release process lock during cleanup: %w", err)
		}
		if err := clearDurableResultState(); err != nil {
			return true, fmt.Errorf("remove durable cleanup marker: %w", err)
		}
	}
	exitProcess(0)
	return true, nil
}

func resumePendingCleanup() bool {
	if !cleanupIsPending() {
		return false
	}
	delay := time.Second
	for {
		_, err := attemptPendingCleanup()
		if err == nil {
			return true
		}
		cleanupSleep(delay)
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func finishFlushAfterAcknowledgement(jobID int, result pendingResult) {
	if err := markCleanupPending(jobID, result); err != nil {
		return
	}
	resumePendingCleanup()
}

func submitResultWithRetry(jobID int, output string, flush bool) {
	reportID, err := newReportID()
	if err != nil {
		return
	}
	result := pendingResult{Output: output, Flush: flush, ReportID: reportID}
	if err := rememberPendingResult(jobID, result); err != nil {
		return
	}
	if err := sendDiagnosticResult(jobID, output, reportID); err != nil {
		if flush && isAgentIdentityGone(err) {
			finishFlushAfterAcknowledgement(jobID, result)
			return
		}
		return
	}
	if flush {
		finishFlushAfterAcknowledgement(jobID, result)
		return
	}
	_ = acknowledgePendingResult(jobID, result)
}

func retryQueuedResults() {
	if cleanupIsPending() {
		return
	}
	resultOutbox.Lock()
	snapshot := make(map[int]pendingResult, len(resultOutbox.pending))
	for id, result := range resultOutbox.pending {
		snapshot[id] = result
	}
	resultOutbox.Unlock()

	for id, result := range snapshot {
		if err := sendDiagnosticResult(id, result.Output, result.ReportID); err != nil {
			if result.Flush && isAgentIdentityGone(err) {
				finishFlushAfterAcknowledgement(id, result)
				return
			}
			continue
		}
		if result.Flush {
			finishFlushAfterAcknowledgement(id, result)
			return
		}
		_ = acknowledgePendingResult(id, result)
	}
}
