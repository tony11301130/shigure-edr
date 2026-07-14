package main

import (
	"strings"
	"testing"
	"time"
)

func validProductionOptions() agentOptions {
	return agentOptions{
		Profile:           "production",
		Server:            "https://edr.intra",
		EnrollToken:       "tenant-bootstrap-token",
		ServerTrust:       "system",
		StatePath:         "state.json",
		SpoolPath:         "spool.jsonl",
		MaxSnapshotEvents: 25,
		Interval:          15 * time.Second,
	}
}

func TestProductionOptionsRejectHTTPServer(t *testing.T) {
	opts := validProductionOptions()
	opts.Server = "http://edr.intra"

	err := validateAgentOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "production requires https server") {
		t.Fatalf("expected production HTTPS validation error, got %v", err)
	}
}

func TestOptionsRequireExplicitProfile(t *testing.T) {
	opts := validProductionOptions()
	opts.Profile = ""

	err := validateAgentOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "profile is required") {
		t.Fatalf("expected explicit profile validation error, got %v", err)
	}
}

func TestProductionOptionsRejectDevEnrollmentToken(t *testing.T) {
	opts := validProductionOptions()
	opts.EnrollToken = "dev-token"

	err := validateAgentOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "production enrollment token") {
		t.Fatalf("expected production enrollment token validation error, got %v", err)
	}
}

func TestProductionOptionsRequireServerTrust(t *testing.T) {
	opts := validProductionOptions()
	opts.ServerTrust = ""

	err := validateAgentOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "production requires server trust") {
		t.Fatalf("expected production server trust validation error, got %v", err)
	}
}

func TestDevOptionsAllowLocalHTTPAndDevToken(t *testing.T) {
	opts := agentOptions{
		Profile:           "dev",
		Server:            "http://127.0.0.1:8765",
		EnrollToken:       "dev-token",
		StatePath:         "state.json",
		SpoolPath:         "spool.jsonl",
		MaxSnapshotEvents: 25,
		Interval:          15 * time.Second,
	}

	if err := validateAgentOptions(opts); err != nil {
		t.Fatalf("expected dev options to remain valid, got %v", err)
	}
}

func TestWindowsServiceCommandLineQuotesPathsWithSpaces(t *testing.T) {
	got := windowsServiceCommandLine(`C:\Program Files\Shiori\shiori-agent.exe`, []string{
		"--server-trust",
		`C:\Program Files\Shigure CA\root.pem`,
	})
	want := `"C:\Program Files\Shiori\shiori-agent.exe" "--server-trust" "C:\Program Files\Shigure CA\root.pem"`
	if got != want {
		t.Fatalf("unexpected command line:\nwant %s\n got %s", want, got)
	}
}

func TestWindowsServiceCommandLineEscapesQuotesAndTrailingSlash(t *testing.T) {
	got := windowsServiceCommandLine(`C:\Agent\agent.exe`, []string{`C:\Trust Bundles\`, `tenant "alpha"`})
	want := `"C:\Agent\agent.exe" "C:\Trust Bundles\\" "tenant \"alpha\""`
	if got != want {
		t.Fatalf("unexpected escaped command line:\nwant %s\n got %s", want, got)
	}
}
