package main

import (
	"os"
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

func TestApplyConfigFileLoadsEnrollmentMaterial(t *testing.T) {
	path := t.TempDir() + "/agent-config.json"
	if err := os.WriteFile(path, []byte(`{"profile":"production","server_url":"https://edr.intra","enrollment_token":"tenant-bootstrap-token","server_trust":"system"}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	opts := agentOptions{ConfigPath: path}

	if err := applyConfigFile(&opts); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if opts.Profile != "production" || opts.Server != "https://edr.intra" || opts.EnrollToken != "tenant-bootstrap-token" || opts.ServerTrust != "system" {
		t.Fatalf("config was not applied: %+v", opts)
	}
	if err := validateAgentOptions(opts); err != nil {
		t.Fatalf("expected config-backed production options to validate: %v", err)
	}
}

func TestApplyConfigFileTreatsMissingEnrollmentTokenAsScrubbed(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/agent-config.json"
	statePath := dir + "/state.json"
	if err := os.WriteFile(configPath, []byte(`{"profile":"production","server_url":"https://edr.intra","server_trust":"system"}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	opts := agentOptions{ConfigPath: configPath, EnrollToken: "dev-token", StatePath: statePath}

	if err := applyConfigFile(&opts); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if opts.EnrollToken != "" {
		t.Fatalf("expected scrubbed config to clear default enrollment token, got %q", opts.EnrollToken)
	}
	if err := validateAgentOptions(opts); err != nil {
		t.Fatalf("expected scrubbed config with existing state to validate: %v", err)
	}
}

func TestProductionScrubbedConfigRequiresExistingState(t *testing.T) {
	opts := validProductionOptions()
	opts.EnrollToken = ""
	opts.StatePath = t.TempDir() + "/missing-state.json"

	err := validateAgentOptions(opts)
	if err == nil || !strings.Contains(err.Error(), "until agent state exists") {
		t.Fatalf("expected missing-state validation error, got %v", err)
	}
}

func TestScrubEnrollmentTokenFromConfigRemovesBootstrapSecret(t *testing.T) {
	path := t.TempDir() + "/agent-config.json"
	if err := os.WriteFile(path, []byte(`{"profile":"production","server_url":"https://edr.intra","enrollment_token":"tenant-bootstrap-token","server_trust":"system"}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := scrubEnrollmentTokenFromConfig(path); err != nil {
		t.Fatalf("scrub config: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scrubbed config: %v", err)
	}
	body := string(b)
	if strings.Contains(body, "enrollment_token") || strings.Contains(body, "tenant-bootstrap-token") {
		t.Fatalf("scrubbed config still contains enrollment material: %s", body)
	}
	if !strings.Contains(body, "https://edr.intra") {
		t.Fatalf("scrubbed config lost server material: %s", body)
	}
}

func TestServiceArgsUseConfigPathInsteadOfEnrollmentTokenWhenConfigured(t *testing.T) {
	opts := validProductionOptions()
	opts.ConfigPath = `C:\ProgramData\Shiori\shiori-agent-config.json`
	got := serviceRuntimeArgs(opts)
	joined := strings.Join(got, " ")

	if !strings.Contains(joined, "--config") {
		t.Fatalf("expected service args to include config path, got %v", got)
	}
	if strings.Contains(joined, "--enroll-token") || strings.Contains(joined, opts.EnrollToken) {
		t.Fatalf("service args leaked enrollment token: %v", got)
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
