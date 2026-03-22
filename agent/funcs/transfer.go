package funcs

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func UploadFile(serverURL, agentID, filePath string) (string, error) {
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(CurrentDir, filePath)
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

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", fmt.Errorf("multipart error: %v", err)
	}
	io.Copy(part, file)

	writer.WriteField("agent_id", agentID)
	writer.WriteField("original_path", filePath)
	writer.Close()

	req, err := http.NewRequest("POST", serverURL+"/api/upload", &body)
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

func DownloadFile(serverURL, fileID, savePath string) (string, error) {
	if !filepath.IsAbs(savePath) {
		savePath = filepath.Join(CurrentDir, savePath)
	}

	resp, err := http.Get(serverURL + "/api/files/" + fileID)
	if err != nil {
		return "", fmt.Errorf("download request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	os.MkdirAll(filepath.Dir(savePath), 0755)

	out, err := os.Create(savePath)
	if err != nil {
		return "", fmt.Errorf("cannot create file: %v", err)
	}
	defer out.Close()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("write error: %v", err)
	}

	return fmt.Sprintf("Saved: %s (%d bytes)", savePath, n), nil
}
