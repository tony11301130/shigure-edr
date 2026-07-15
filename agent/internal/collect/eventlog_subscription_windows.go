//go:build windows

package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
)

func startPlatformWindowsEventLogSource(ctx context.Context, subscriber *WindowsEventLogSubscriber) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", windowsEventLogSubscriptionScript)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var record WindowsEventLogRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				subscriber.setLastError(err)
				continue
			}
			subscriber.Enqueue(record)
		}
		if err := scanner.Err(); err != nil {
			subscriber.setLastError(err)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				subscriber.setLastError(errors.New(line))
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		if ctx.Err() == nil {
			if err != nil {
				subscriber.setLastError(err)
			} else {
				subscriber.setLastError(errors.New("windows event log subscription source exited"))
			}
			subscriber.Stop()
		}
	}()
	return nil
}

const windowsEventLogSubscriptionScript = `
$ErrorActionPreference = 'Stop'
$profiles = @(
  @{Name='powershell_operational'; LogName='Microsoft-Windows-PowerShell/Operational'; Query='*[System[(EventID=4103 or EventID=4104)]]'},
  @{Name='security_auth'; LogName='Security'; Query='*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]'},
  @{Name='service_control_manager'; LogName='System'; Query='*[System[(EventID=7045)]]'},
  @{Name='task_scheduler'; LogName='Microsoft-Windows-TaskScheduler/Operational'; Query='*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]'}
)
$watchers = @()
try {
  foreach ($profile in $profiles) {
    try {
      $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($profile.LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $profile.Query)
      $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)
      Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier $profile.Name | Out-Null
      $watcher.Enabled = $true
      $watchers += $watcher
    } catch {
      [Console]::Error.WriteLine(("eventlog subscription start failed for {0}: {1}" -f $profile.Name, $_.Exception.Message))
    }
  }
  while ($true) {
    $event = Wait-Event -Timeout 1
    if ($null -eq $event) { continue }
    $record = $event.SourceEventArgs.EventRecord
    if ($null -ne $record) {
      $message = ''
      try { $message = $record.FormatDescription() } catch { $message = '' }
      [pscustomobject]@{
        Query = $event.SourceIdentifier
        LogName = $record.LogName
        EventID = $record.Id
        RecordID = $record.RecordId
        ProviderName = $record.ProviderName
        TimeCreated = $(if ($record.TimeCreated) { $record.TimeCreated.ToUniversalTime().ToString('o') } else { '' })
        Message = $message
      } | ConvertTo-Json -Compress
    }
    Remove-Event -EventIdentifier $event.EventIdentifier
  }
} finally {
  foreach ($watcher in $watchers) {
    try { $watcher.Enabled = $false } catch {}
    try { $watcher.Dispose() } catch {}
  }
  foreach ($profile in $profiles) {
    try { Unregister-Event -SourceIdentifier $profile.Name -ErrorAction SilentlyContinue } catch {}
  }
}
`
