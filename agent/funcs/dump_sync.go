package funcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func SubmitCrashDump(uploadURL, endpointID, agentSecret, filePath string, keyID string, encKey []byte) (string, error) {
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(getCurrentDir(), filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %v", err)
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat file: %v", err)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("cannot upload a directory")
	}

	fileData, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("file read error: %v", err)
	}

	sum := sha256.Sum256(fileData)
	meta, err := json.Marshal(map[string]string{
		"agent_id":     endpointID,
		"agent_secret": agentSecret,
		"sha256":       hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return "", fmt.Errorf("marshal error: %v", err)
	}
	enc, err := SealTelemetry(encKey, meta)
	if err != nil {
		return "", fmt.Errorf("seal error: %v", err)
	}
	authJSON, err := json.Marshal(map[string]string{"kid": keyID, "data": enc})
	if err != nil {
		return "", fmt.Errorf("auth marshal error: %v", err)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", fmt.Errorf("multipart error: %v", err)
	}
	if _, err := part.Write(fileData); err != nil {
		return "", fmt.Errorf("multipart write error: %v", err)
	}

	writer.WriteField("agent_id", endpointID)
	writer.WriteField("original_path", filePath)
	writer.WriteField("auth", string(authJSON))
	writer.Close()

	req, err := http.NewRequest("POST", uploadURL, &body)
	if err != nil {
		return "", fmt.Errorf("request error: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	return fmt.Sprintf("Uploaded: %s (%d bytes)", filepath.Base(filePath), fi.Size()), nil
}

func FetchUpdatePackage(filesURL, fileID, savePath, endpointID, agentSecret string, taskID int) (string, error) {
	if !filepath.IsAbs(savePath) {
		savePath = filepath.Join(getCurrentDir(), savePath)
	}

	req, err := http.NewRequest("GET", filesURL+fileID, nil)
	if err != nil {
		return "", fmt.Errorf("download request error: %v", err)
	}
	req.Header.Set("X-Agent-ID", endpointID)
	req.Header.Set("X-Task-ID", fmt.Sprint(taskID))
	req.Header.Set("Authorization", "Bearer "+agentSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	if err := os.MkdirAll(filepath.Dir(savePath), 0755); err != nil {
		return "", fmt.Errorf("cannot create directory: %v", err)
	}

	// Stage beside the destination: a failed response must never truncate the
	// existing file. Reject nonregular destinations instead of following links.
	mode := os.FileMode(0600)
	if info, err := os.Lstat(savePath); err == nil {
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("destination is not a regular file")
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot inspect destination: %w", err)
	}
	out, err := os.CreateTemp(filepath.Dir(savePath), ".download-*")
	if err != nil {
		return "", fmt.Errorf("cannot create file: %v", err)
	}
	tempPath := out.Name()
	defer func() {
		out.Close()
		os.Remove(tempPath)
	}()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("write error: %v", err)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return "", fmt.Errorf("incomplete download: got %d bytes, expected %d", n, resp.ContentLength)
	}
	if err := out.Chmod(mode); err != nil {
		return "", fmt.Errorf("cannot set file permissions: %w", err)
	}
	if err := out.Sync(); err != nil {
		return "", fmt.Errorf("cannot sync file: %w", err)
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("cannot close file: %w", err)
	}
	if err := os.Rename(tempPath, savePath); err != nil {
		return "", fmt.Errorf("cannot replace destination: %w", err)
	}

	return fmt.Sprintf("Saved: %s (%d bytes)", savePath, n), nil
}
