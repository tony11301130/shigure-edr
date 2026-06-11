package tasks

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func serviceList() []map[string]any {
	if runtime.GOOS == "windows" {
		out, err := runCommand(20*time.Second, "sc.exe", "query", "state=", "all")
		row := map[string]any{"format": "sc_query", "output": out}
		if err != nil {
			row["error"] = err.Error()
		}
		return []map[string]any{row}
	}
	if runtime.GOOS != "linux" {
		return []map[string]any{{"note": "native service collector for this OS is pending"}}
	}
	roots := []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".service") || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, map[string]any{"name": name, "source": root})
			if len(out) >= 200 {
				return out
			}
		}
	}
	return out
}

func scheduledTasks() []map[string]any {
	out := []map[string]any{}
	if runtime.GOOS == "windows" {
		out, err := runCommand(20*time.Second, "schtasks.exe", "/query", "/fo", "csv", "/v")
		row := map[string]any{"format": "schtasks_csv", "output": out}
		if err != nil {
			row["error"] = err.Error()
		}
		return []map[string]any{row}
	}
	if runtime.GOOS != "linux" {
		return []map[string]any{{"note": "native scheduled task collector for this OS is pending"}}
	}
	paths := []string{"/etc/crontab"}
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, map[string]any{"path": p, "type": "crontab"})
		}
	}
	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			out = append(out, map[string]any{"path": filepath.Join(dir, e.Name()), "type": "cron"})
		}
	}
	return out
}

func windowsEventLogs(args map[string]any) (map[string]any, error) {
	profile, _ := args["profile"].(string)
	if profile == "" {
		profile = "powershell"
	}
	maxEvents := intArg(args, "max_events", 25)
	if maxEvents <= 0 {
		maxEvents = 25
	}
	if maxEvents > 100 {
		maxEvents = 100
	}
	return platformWindowsEventLogs(profile, maxEvents)
}

func registryQuery(args map[string]any) (map[string]any, error) {
	key, _ := args["key"].(string)
	if key == "" {
		return nil, errors.New("key required")
	}
	if runtime.GOOS != "windows" {
		return map[string]any{"platform": runtime.GOOS, "unsupported": true, "reason": "registry_query is only available on Windows", "key": key}, nil
	}
	cmdArgs := []string{"query", key}
	if boolArg(args, "recursive", false) {
		cmdArgs = append(cmdArgs, "/s")
	}
	out, err := runCommand(20*time.Second, "reg.exe", cmdArgs...)
	return map[string]any{"platform": "windows", "key": key, "recursive": boolArg(args, "recursive", false), "output": out}, err
}

func autorunsCollect() (map[string]any, error) {
	if runtime.GOOS == "windows" {
		ps := `$ErrorActionPreference="SilentlyContinue"; $r=[ordered]@{}; $keys=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"); $r.run_keys=@(); foreach($k in $keys){ $item=Get-ItemProperty -Path $k; if($item){ $r.run_keys += @{path=$k; values=$item} } }; $r.startup_folders=@(); @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup") | % { if(Test-Path $_){ $r.startup_folders += @{path=$_; entries=(Get-ChildItem $_ | Select Name,FullName,Length,LastWriteTime)} } }; $r.services=Get-CimInstance Win32_Service | Select Name,State,StartMode,PathName,StartName; $r.scheduled_tasks=schtasks.exe /query /fo csv /v; $r | ConvertTo-Json -Depth 5 -Compress`
		out, err := runCommand(30*time.Second, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
		return map[string]any{"platform": "windows", "format": "autoruns_json", "output": out}, err
	}
	paths := []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly", "/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/profile", "/etc/profile.d"}
	items := []map[string]any{}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, _ := os.ReadDir(path)
			for _, e := range entries {
				items = append(items, map[string]any{"path": filepath.Join(path, e.Name()), "source": path, "is_dir": e.IsDir()})
				if len(items) >= 500 {
					return map[string]any{"platform": runtime.GOOS, "items": items, "truncated": true}, nil
				}
			}
		} else {
			items = append(items, map[string]any{"path": path, "source": path, "size": info.Size(), "mod_time": info.ModTime().UTC().Format(time.RFC3339)})
		}
	}
	return map[string]any{"platform": runtime.GOOS, "items": items}, nil
}

func agentIdentity() (map[string]any, error) {
	if runtime.GOOS == "windows" {
		out, err := runCommand(5*time.Second, "whoami.exe", "/all")
		return map[string]any{"platform": runtime.GOOS, "whoami_all": out, "is_local_system_hint": strings.Contains(strings.ToLower(out), "nt authority\\system")}, err
	}
	out, err := runCommand(5*time.Second, "id")
	return map[string]any{"platform": runtime.GOOS, "id": out, "is_root_hint": strings.Contains(out, "uid=0(")}, err
}
