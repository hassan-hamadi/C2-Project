package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"endpoint-telemetry/funcs"
)

func configureResultAcknowledgementTest(t *testing.T) {
	t.Helper()
	previousEndpoint := TelemetryEndpoint
	previousPath := PathResult
	previousKey := append([]byte(nil), EncryptionKey...)
	previousKeyID := KeyID
	previousEndpointID := EndpointID
	previousSecret := AgentSecret
	previousClient := http.DefaultClient
	t.Cleanup(func() {
		TelemetryEndpoint = previousEndpoint
		PathResult = previousPath
		EncryptionKey = previousKey
		KeyID = previousKeyID
		EndpointID = previousEndpointID
		AgentSecret = previousSecret
		http.DefaultClient = previousClient
	})

	EncryptionKey = bytes.Repeat([]byte{0x5a}, 32)
	KeyID = "fixture-key-id"
	EndpointID = "fixture-agent"
	AgentSecret = "11" + string(bytes.Repeat([]byte{'2'}, 62))
	PathResult = "/result"
}

func TestSubmitDiagnosticReportRequiresMatchingAuthenticatedAcknowledgement(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const output = "saved output"

	tests := []struct {
		name      string
		output    string
		mutate    func(*ResultAcknowledgement, *string)
		rawBody   string
		wantError bool
	}{
		{name: "valid"},
		{name: "valid idempotent retry", mutate: func(a *ResultAcknowledgement, _ *string) { a.AlreadyRecorded = true }},
		{name: "valid normalized UTF-8", output: string([]byte{'a', 0xff, 0xfe, 'b'})},
		{name: "plain 200", rawBody: "OK", wantError: true},
		{name: "malformed JSON", rawBody: "{", wantError: true},
		{name: "wrong key ID", mutate: func(_ *ResultAcknowledgement, kid *string) { *kid = "other-key" }, wantError: true},
		{name: "invalid ciphertext", rawBody: `{"kid":"fixture-key-id","data":"not-ciphertext"}`, wantError: true},
		{name: "wrong status", mutate: func(a *ResultAcknowledgement, _ *string) { a.Status = "accepted" }, wantError: true},
		{name: "wrong agent", mutate: func(a *ResultAcknowledgement, _ *string) { a.EndpointID = "other-agent" }, wantError: true},
		{name: "wrong task", mutate: func(a *ResultAcknowledgement, _ *string) { a.JobID++ }, wantError: true},
		{name: "wrong report ID", mutate: func(a *ResultAcknowledgement, _ *string) { a.ReportID = string(bytes.Repeat([]byte{'f'}, 64)) }, wantError: true},
		{name: "wrong output digest", mutate: func(a *ResultAcknowledgement, _ *string) { a.OutputSHA256 = string(bytes.Repeat([]byte{'0'}, 64)) }, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configureResultAcknowledgementTest(t)
			testOutput := test.output
			if testOutput == "" {
				testOutput = output
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestBody, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var envelope struct {
					Data string `json:"data"`
				}
				if err := json.Unmarshal(requestBody, &envelope); err != nil {
					t.Fatal(err)
				}
				plain, err := funcs.UnsealTelemetry(EncryptionKey, envelope.Data)
				if err != nil {
					t.Fatal(err)
				}
				var submitted DiagnosticOutput
				if err := json.Unmarshal(plain, &submitted); err != nil {
					t.Fatal(err)
				}
				if submitted.ReportID != reportID {
					t.Fatalf("submitted report ID = %q", submitted.ReportID)
				}
				if submitted.Output != string([]rune(testOutput)) {
					t.Fatalf("submitted output was not normalized: %q", submitted.Output)
				}

				w.Header().Set("Content-Type", "application/json")
				if test.rawBody != "" {
					_, _ = io.WriteString(w, test.rawBody)
					return
				}
				digest := sha256.Sum256([]byte(submitted.Output))
				acknowledgement := ResultAcknowledgement{
					Status:       "ok",
					EndpointID:   EndpointID,
					JobID:        submitted.JobID,
					ReportID:     submitted.ReportID,
					OutputSHA256: hex.EncodeToString(digest[:]),
				}
				kid := KeyID
				if test.mutate != nil {
					test.mutate(&acknowledgement, &kid)
				}
				encoded, err := json.Marshal(acknowledgement)
				if err != nil {
					t.Fatal(err)
				}
				ciphertext, err := funcs.SealTelemetry(EncryptionKey, encoded)
				if err != nil {
					t.Fatal(err)
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"kid": kid, "data": ciphertext})
			}))
			defer server.Close()
			TelemetryEndpoint = server.URL
			http.DefaultClient = server.Client()

			err := SubmitDiagnosticReport(42, testOutput, reportID)
			if test.wantError && err == nil {
				t.Fatal("unverified acknowledgement was accepted")
			}
			if !test.wantError && err != nil {
				t.Fatalf("valid acknowledgement rejected: %v", err)
			}
		})
	}
}

func TestFlushRetainsResultWhenHTTP200AcknowledgementIsUnverified(t *testing.T) {
	configureDurableResultTest(t)
	previousEndpoint := TelemetryEndpoint
	previousPath := PathResult
	previousClient := http.DefaultClient
	t.Cleanup(func() {
		TelemetryEndpoint = previousEndpoint
		PathResult = previousPath
		http.DefaultClient = previousClient
	})
	wiped := false
	purgeLocalInstallation = func(string) (bool, error) { return false, nil }
	exitProcess = func(int) { wiped = true }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	}))
	defer server.Close()
	TelemetryEndpoint = server.URL
	PathResult = "/result"
	http.DefaultClient = server.Client()
	sendDiagnosticResult = SubmitDiagnosticReport

	submitResultWithRetry(77, "Cache flush acknowledged. Cleaning up…", true)
	if wiped {
		t.Fatal("flush wiped after an unverified HTTP 200 acknowledgement")
	}
	resultOutbox.Lock()
	_, queued := resultOutbox.pending[77]
	resultOutbox.Unlock()
	if !queued {
		t.Fatal("flush result was removed after an unverified HTTP 200 acknowledgement")
	}
}
