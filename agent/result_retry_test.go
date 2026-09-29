package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func configureDurableResultTest(t *testing.T) string {
	t.Helper()
	previousSender := sendDiagnosticResult
	previousOverride := resultStatePathOverride
	previousKey := append([]byte(nil), EncryptionKey...)
	previousKeyID := KeyID
	previousEndpoint := EndpointID
	previousSecret := AgentSecret
	previousPurge := purgeLocalInstallation
	previousExit := exitProcess
	previousSleep := cleanupSleep
	t.Cleanup(func() {
		_ = releaseAgentProcessLock(true)
		sendDiagnosticResult = previousSender
		resultStatePathOverride = previousOverride
		EncryptionKey = previousKey
		KeyID = previousKeyID
		EndpointID = previousEndpoint
		AgentSecret = previousSecret
		purgeLocalInstallation = previousPurge
		exitProcess = previousExit
		cleanupSleep = previousSleep
		resetDurableResultMemory()
	})

	base := filepath.Join(t.TempDir(), "state", "result")
	resultStatePathOverride = base
	EncryptionKey = bytes.Repeat([]byte{0x42}, 32)
	KeyID = "fixture-build-key"
	EndpointID = "fixture-agent-original"
	AgentSecret = "11" + string(bytes.Repeat([]byte{'2'}, 62))
	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestAgentProcessLockHelper(t *testing.T) {
	if os.Getenv("ENDPOINT_TELEMETRY_LOCK_HELPER") != "1" {
		return
	}
	resultStatePathOverride = os.Getenv("ENDPOINT_TELEMETRY_LOCK_BASE")
	if err := acquireAgentProcessLock(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, "locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = releaseAgentProcessLock(false)
	os.Exit(0)
}

func TestProcessLockRejectsConcurrentProcessAndRecoversAfterExit(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state", "result")
	previousOverride := resultStatePathOverride
	resultStatePathOverride = base
	t.Cleanup(func() {
		_ = releaseAgentProcessLock(true)
		resultStatePathOverride = previousOverride
	})

	cmd := exec.Command(os.Args[0], "-test.run=^TestAgentProcessLockHelper$")
	cmd.Env = append(os.Environ(),
		"ENDPOINT_TELEMETRY_LOCK_HELPER=1",
		"ENDPOINT_TELEMETRY_LOCK_BASE="+base,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("helper did not acquire lock: line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	if err := acquireAgentProcessLock(); !errors.Is(err, errAgentAlreadyRunning) {
		t.Fatalf("concurrent acquire error = %v, want errAgentAlreadyRunning", err)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed lock helper exited successfully")
	}
	cmd.Process = nil
	_ = stdin.Close()

	if err := acquireAgentProcessLock(); err != nil {
		t.Fatalf("OS did not release lock after process exit: %v", err)
	}
	lockPath := processLockPath(base)
	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("lock mode = %o, want 600", info.Mode().Perm())
	}
	if err := releaseAgentProcessLock(false); err != nil {
		t.Fatal(err)
	}
	if err := acquireAgentProcessLock(); err != nil {
		t.Fatalf("leftover unlocked lock file blocked restart: %v", err)
	}
}

func TestProcessLockFileIsExcludedFromDurableGenerations(t *testing.T) {
	base := configureDurableResultTest(t)
	if err := os.WriteFile(processLockPath(base), nil, 0600); err != nil {
		t.Fatal(err)
	}
	files, err := durableStateFiles(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] == processLockPath(base) {
		t.Fatalf("durable generations included process lock: %v", files)
	}
}

func TestUnixCleanupRemovesProcessLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cleanup is deferred to the helper")
	}
	base := configureDurableResultTest(t)
	if err := acquireAgentProcessLock(); err != nil {
		t.Fatal(err)
	}
	result := pendingResult{Output: "flush", Flush: true, ReportID: string(bytes.Repeat([]byte{'c'}, 64))}
	if err := rememberPendingResult(34, result); err != nil {
		t.Fatal(err)
	}
	if err := markCleanupPending(34, result); err != nil {
		t.Fatal(err)
	}
	purgeLocalInstallation = func(string) (bool, error) { return false, nil }
	exitProcess = func(int) {}

	if attempted, err := attemptPendingCleanup(); err != nil || !attempted {
		t.Fatalf("cleanup = attempted:%v err:%v", attempted, err)
	}
	if _, err := os.Stat(processLockPath(base)); !os.IsNotExist(err) {
		t.Fatalf("process lock remains after cleanup: %v", err)
	}
}

func resetDurableResultMemory() {
	resultOutbox.Lock()
	resultOutbox.pending = make(map[int]pendingResult)
	resultOutbox.cleanupPending = false
	resultOutbox.initialized = false
	resultOutbox.sequence = 0
	resultOutbox.Unlock()
}

func TestFailedResultSurvivesRestartWithoutRerunningTask(t *testing.T) {
	base := configureDurableResultTest(t)
	originalID, originalSecret := EndpointID, AgentSecret
	attempts := 0
	reportID := ""
	sendDiagnosticResult = func(id int, output, submittedReportID string) error {
		if id != 42 || output != "saved output" {
			t.Fatalf("unexpected result: id=%d output=%q", id, output)
		}
		if reportID == "" {
			reportID = submittedReportID
		} else if submittedReportID != reportID {
			t.Fatalf("report ID changed across retry: %q != %q", submittedReportID, reportID)
		}
		if len(submittedReportID) != 64 {
			t.Fatalf("report ID length = %d, want 64", len(submittedReportID))
		}
		attempts++
		if attempts == 1 {
			return errors.New("lost acknowledgement")
		}
		return nil
	}

	submitResultWithRetry(42, "saved output", false)
	files, _ := durableStateFiles(base)
	if len(files) != 1 {
		t.Fatalf("got %d state generations, want 1", len(files))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("saved output")) || bytes.Contains(raw, []byte(originalSecret)) {
		t.Fatal("durable state contains plaintext result or secret")
	}
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	if dirInfo, _ := os.Stat(filepath.Dir(base)); dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("state directory mode = %o, want 700", dirInfo.Mode().Perm())
	}

	EndpointID = "new-random-agent"
	AgentSecret = "33" + string(bytes.Repeat([]byte{'4'}, 62))
	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatal(err)
	}
	if EndpointID != originalID || AgentSecret != originalSecret {
		t.Fatal("restart did not restore the identity needed to submit queued results")
	}
	resultOutbox.Lock()
	_, queued := resultOutbox.pending[42]
	resultOutbox.Unlock()
	if !queued {
		t.Fatal("failed result was not restored after restart")
	}

	retryQueuedResults()
	retryQueuedResults()
	if attempts != 2 {
		t.Fatalf("got %d submissions; want one failed attempt and one retry", attempts)
	}

	EndpointID = "another-random-agent"
	AgentSecret = "55" + string(bytes.Repeat([]byte{'6'}, 62))
	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatal(err)
	}
	resultOutbox.Lock()
	remaining := len(resultOutbox.pending)
	resultOutbox.Unlock()
	if remaining != 0 || EndpointID != originalID || AgentSecret != originalSecret {
		t.Fatalf("restart state = pending:%d id:%q", remaining, EndpointID)
	}
}

func TestLegacyDurableResultGetsPersistentReportID(t *testing.T) {
	base := configureDurableResultTest(t)
	resultOutbox.Lock()
	resultOutbox.pending[23] = pendingResult{Output: "legacy output"}
	if err := persistDurableStateLocked(); err != nil {
		resultOutbox.Unlock()
		t.Fatal(err)
	}
	resultOutbox.Unlock()

	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatal(err)
	}
	resultOutbox.Lock()
	migrated := resultOutbox.pending[23]
	resultOutbox.Unlock()
	if len(migrated.ReportID) != 64 {
		t.Fatalf("migrated report ID length = %d, want 64", len(migrated.ReportID))
	}

	files, err := durableStateFiles(base)
	if err != nil || len(files) != 1 {
		t.Fatalf("durable generations = %v, %v", files, err)
	}
	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatal(err)
	}
	resultOutbox.Lock()
	reloaded := resultOutbox.pending[23]
	resultOutbox.Unlock()
	if reloaded.ReportID != migrated.ReportID {
		t.Fatal("migrated report ID was not persisted")
	}
}

func TestDurableStateFallsBackToValidGenerationAndFailsClosedWhenAllCorrupt(t *testing.T) {
	base := configureDurableResultTest(t)
	valid, _ := durableStateFiles(base)
	if err := os.WriteFile(base+".corrupt", []byte("not ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatalf("valid older generation was not recovered: %v", err)
	}

	for _, path := range valid {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	resetDurableResultMemory()
	EndpointID = "must-not-be-published"
	if err := initializeDurableResultState(); err == nil {
		t.Fatal("unauthenticated durable state was silently replaced")
	}
	files, _ := durableStateFiles(base)
	if len(files) != 1 || filepath.Base(files[0]) != filepath.Base(base)+".corrupt" {
		t.Fatalf("corrupt state was modified: %v", files)
	}
}

func TestClearDurableStateRemovesEveryGeneration(t *testing.T) {
	base := configureDurableResultTest(t)
	if err := os.WriteFile(base+".stale", []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := clearDurableResultState(); err != nil {
		t.Fatal(err)
	}
	files, _ := durableStateFiles(base)
	if len(files) != 0 {
		t.Fatalf("durable state remains after cleanup: %v", files)
	}
}

func TestFlushTreatsGoneIdentityAsLocalSuccess(t *testing.T) {
	configureDurableResultTest(t)
	wiped := false
	purgeLocalInstallation = func(string) (bool, error) { return false, nil }
	exitProcess = func(int) { wiped = true }
	sendDiagnosticResult = func(id int, output, reportID string) error {
		return &errAgentIdentityGone{StatusCode: 403, Body: `{"error":"Invalid agent identity"}`}
	}

	submitResultWithRetry(7, "Cache flush acknowledged. Cleaning up…", true)
	if !wiped {
		t.Fatal("flush did not wipe after identity-gone response")
	}
	resultOutbox.Lock()
	remaining := len(resultOutbox.pending)
	resultOutbox.Unlock()
	if remaining != 0 {
		t.Fatalf("flush pending remained after identity-gone wipe: %d", remaining)
	}
}

func TestFlushKeepsRetryingOnTransientErrors(t *testing.T) {
	configureDurableResultTest(t)
	wiped := false
	purgeLocalInstallation = func(string) (bool, error) { return false, nil }
	exitProcess = func(int) { wiped = true }
	sendDiagnosticResult = func(id int, output, reportID string) error {
		return errors.New("post: connection reset")
	}

	submitResultWithRetry(8, "Cache flush acknowledged. Cleaning up…", true)
	if wiped {
		t.Fatal("flush wiped on a transient transport error")
	}
	resultOutbox.Lock()
	_, queued := resultOutbox.pending[8]
	resultOutbox.Unlock()
	if !queued {
		t.Fatal("flush result was not retained for retry")
	}
}

func TestNonFlushGoneIdentityDoesNotWipe(t *testing.T) {
	configureDurableResultTest(t)
	wiped := false
	purgeLocalInstallation = func(string) (bool, error) { return false, nil }
	exitProcess = func(int) { wiped = true }
	sendDiagnosticResult = func(id int, output, reportID string) error {
		return &errAgentIdentityGone{StatusCode: 403, Body: `{"error":"Invalid agent identity"}`}
	}

	submitResultWithRetry(9, "ordinary output", false)
	if wiped {
		t.Fatal("non-flush result triggered local wipe")
	}
	resultOutbox.Lock()
	_, queued := resultOutbox.pending[9]
	resultOutbox.Unlock()
	if !queued {
		t.Fatal("ordinary result was not retained after identity-gone failure")
	}
}

func TestCleanupFailureRetainsDurableMarkerAndRetries(t *testing.T) {
	base := configureDurableResultTest(t)
	purgeCalls := 0
	sleepCalls := 0
	exited := false
	purgeLocalInstallation = func(gotBase string) (bool, error) {
		if gotBase != base {
			t.Fatalf("cleanup base = %q, want %q", gotBase, base)
		}
		purgeCalls++
		if purgeCalls == 1 {
			return false, errors.New("injected removal failure")
		}
		return false, nil
	}
	cleanupSleep = func(_ time.Duration) {
		sleepCalls++
		state, err := loadDurableStateLocked(base)
		if err != nil {
			t.Fatalf("load cleanup marker: %v", err)
		}
		if !state.CleanupPending || len(state.Pending) != 0 {
			t.Fatalf("failure state = cleanup:%v pending:%d", state.CleanupPending, len(state.Pending))
		}
	}
	exitProcess = func(int) { exited = true }
	sendDiagnosticResult = func(int, string, string) error { return nil }

	submitResultWithRetry(31, "flush", true)
	if purgeCalls != 2 || sleepCalls != 1 || !exited {
		t.Fatalf("cleanup attempts=%d sleeps=%d exited=%v", purgeCalls, sleepCalls, exited)
	}
	files, err := durableStateFiles(base)
	if err != nil || len(files) != 0 {
		t.Fatalf("successful cleanup left state: %v, %v", files, err)
	}
}

func TestRestartResumesCleanupWithoutSubmittingResults(t *testing.T) {
	configureDurableResultTest(t)
	result := pendingResult{Output: "flush", Flush: true, ReportID: string(bytes.Repeat([]byte{'a'}, 64))}
	if err := rememberPendingResult(32, result); err != nil {
		t.Fatal(err)
	}
	if err := markCleanupPending(32, result); err != nil {
		t.Fatal(err)
	}

	resetDurableResultMemory()
	if err := initializeDurableResultState(); err != nil {
		t.Fatal(err)
	}
	if !cleanupIsPending() {
		t.Fatal("cleanup marker was not restored on restart")
	}
	submissions := 0
	sendDiagnosticResult = func(int, string, string) error {
		submissions++
		return nil
	}
	purgeLocalInstallation = func(string) (bool, error) { return false, nil }
	exited := false
	exitProcess = func(int) { exited = true }

	if !resumePendingCleanup() || !exited {
		t.Fatal("restart did not resume pending cleanup")
	}
	if submissions != 0 {
		t.Fatalf("cleanup restart submitted %d network result(s)", submissions)
	}
}

func TestDeferredWindowsCleanupLeavesMarkerForHelper(t *testing.T) {
	base := configureDurableResultTest(t)
	result := pendingResult{Output: "flush", Flush: true, ReportID: string(bytes.Repeat([]byte{'b'}, 64))}
	if err := rememberPendingResult(33, result); err != nil {
		t.Fatal(err)
	}
	if err := markCleanupPending(33, result); err != nil {
		t.Fatal(err)
	}
	purgeLocalInstallation = func(string) (bool, error) { return true, nil }
	exited := false
	exitProcess = func(int) { exited = true }

	attempted, err := attemptPendingCleanup()
	if err != nil || !attempted || !exited {
		t.Fatalf("deferred cleanup = attempted:%v exited:%v err:%v", attempted, exited, err)
	}
	state, err := loadDurableStateLocked(base)
	if err != nil || !state.CleanupPending {
		t.Fatalf("helper marker missing: cleanup:%v err:%v", state != nil && state.CleanupPending, err)
	}
}
