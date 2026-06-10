package agentapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type EnrollmentRequest struct {
	EnrollmentToken string         `json:"enrollment_token"`
	PublicKey       string         `json:"public_key,omitempty"`
	Host            string         `json:"host"`
	IPAddress       string         `json:"ip_address,omitempty"`
	OS              string         `json:"os,omitempty"`
	AgentVersion    string         `json:"agent_version"`
	Metadata        map[string]any `json:"metadata"`
}

type EnrollmentResponse struct {
	TenantID   string         `json:"tenant_id"`
	AgentID    string         `json:"agent_id"`
	AgentToken string         `json:"agent_token"`
	Config     map[string]any `json:"config"`
}

type NormalizedEvent struct {
	Source          string         `json:"source"`
	EventType       string         `json:"event_type"`
	TenantID        string         `json:"tenant_id"`
	SourceEventID   string         `json:"source_event_id,omitempty"`
	Host            string         `json:"host,omitempty"`
	User            string         `json:"user,omitempty"`
	ProcessName     string         `json:"process_name,omitempty"`
	ProcessID       string         `json:"process_id,omitempty"`
	ParentProcessID string         `json:"parent_process_id,omitempty"`
	CommandLine     string         `json:"command_line,omitempty"`
	FilePath        string         `json:"file_path,omitempty"`
	Domain          string         `json:"domain,omitempty"`
	RemoteIP        string         `json:"remote_ip,omitempty"`
	RemotePort      *int           `json:"remote_port,omitempty"`
	Severity        string         `json:"severity"`
	Mitre           []string       `json:"mitre,omitempty"`
	Raw             map[string]any `json:"raw"`
}

type AgentConfig struct {
	Version                 int            `json:"version"`
	TaskPollSeconds         int            `json:"task_poll_seconds"`
	HeartbeatSeconds        int            `json:"heartbeat_seconds"`
	UploadIntervalSeconds   int            `json:"upload_interval_seconds"`
	MaxSnapshotEvents       int            `json:"max_snapshot_events"`
	CollectSnapshot         bool           `json:"collect_snapshot"`
	CollectProcessSnapshot  bool           `json:"collect_process_snapshot"`
	CollectNetworkSnapshot  bool           `json:"collect_network_snapshot"`
	CollectWindowsEventLogs bool           `json:"collect_windows_event_logs"`
	DemoSuspiciousEvent     bool           `json:"demo_suspicious_event"`
	Features                map[string]any `json:"features"`
}

type HeartbeatResponse struct {
	Status        string      `json:"status"`
	TasksPending  bool        `json:"tasks_pending"`
	ConfigVersion int         `json:"config_version"`
	Config        AgentConfig `json:"config"`
}

type Task struct {
	TaskID   string         `json:"task_id"`
	TenantID string         `json:"tenant_id"`
	AgentID  string         `json:"agent_id"`
	TaskType string         `json:"task_type"`
	Args     map[string]any `json:"args"`
	Status   string         `json:"status"`
}

func (c *Client) Enroll(req EnrollmentRequest) (*EnrollmentResponse, error) {
	var out EnrollmentResponse
	if err := c.do("POST", "/api/v1/enroll", "", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Heartbeat(agentID, token string, body map[string]any) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	err := c.do("POST", "/api/v1/agents/"+agentID+"/heartbeat", token, body, &out)
	return &out, err
}

func (c *Client) IngestEvents(agentID, token string, events []NormalizedEvent) error {
	return c.do("POST", "/api/v1/agents/"+agentID+"/events", token, map[string]any{"events": events}, &map[string]any{})
}

func (c *Client) ClaimTasks(agentID, token string, max int) ([]Task, error) {
	var out struct {
		Tasks []Task `json:"tasks"`
	}
	err := c.do("POST", "/api/v1/agents/"+agentID+"/tasks/claim", token, map[string]any{"max_tasks": max}, &out)
	return out.Tasks, err
}

func (c *Client) SendTaskResult(agentID, token, taskID, status string, result map[string]any, msg string) error {
	body := map[string]any{"status": status, "result": result}
	if msg != "" {
		body["error"] = msg
	}
	return c.do("POST", "/api/v1/agents/"+agentID+"/tasks/"+taskID+"/result", token, body, &map[string]any{})
}

func (c *Client) do(method, path, token string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%s %s failed: %s", method, path, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(out)
}
