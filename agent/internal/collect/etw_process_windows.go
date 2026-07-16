//go:build windows

package collect

import (
	"context"
	"errors"
	"os/exec"
)

func startPlatformETWProcessSource(ctx context.Context, collector *ETWProcessCollector) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", windowsETWProcessSourceScript)
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

	collector.ingestJSONLines(stdout, stderr)
	go func() {
		err := cmd.Wait()
		if ctx.Err() == nil {
			if err != nil {
				collector.setLastError(err)
			} else {
				collector.setLastError(errors.New("windows process trace source exited"))
			}
			collector.Stop()
		}
	}()
	return nil
}

const windowsETWProcessSourceScript = `
$ErrorActionPreference = 'Stop'
function Convert-TraceTime($value) {
  if ($null -eq $value) { return '' }
  try {
    $ticks = [UInt64]$value
    return [DateTime]::FromFileTimeUtc([Int64]$ticks).ToString('o')
  } catch {
    return ''
  }
}
function Get-ProcessDetails($processId) {
  try {
    return Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [int]$processId) -ErrorAction Stop
  } catch {
    return $null
  }
}
$hostName = [Environment]::MachineName
try {
  Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier ShigureProcessStartTrace | Out-Null
  Register-WmiEvent -Class Win32_ProcessStopTrace -SourceIdentifier ShigureProcessStopTrace | Out-Null
  while ($true) {
    $event = Wait-Event -Timeout 1
    if ($null -eq $event) { continue }
    $trace = $event.SourceEventArgs.NewEvent
    if ($null -ne $trace) {
      $isStop = $event.SourceIdentifier -eq 'ShigureProcessStopTrace'
      $details = $null
      if (-not $isStop) { $details = Get-ProcessDetails $trace.ProcessID }
      [pscustomobject]@{
        Kind = $(if ($isStop) { 'process_stop' } else { 'process_start' })
        Host = $hostName
        ProcessID = [uint32]$trace.ProcessID
        ParentProcessID = $(if ($trace.PSObject.Properties.Name -contains 'ParentProcessID') { [uint32]$trace.ParentProcessID } else { [uint32]0 })
        ProcessName = $(if ($details -and $details.Name) { $details.Name } else { [string]$trace.ProcessName })
        ImagePath = $(if ($details -and $details.ExecutablePath) { [string]$details.ExecutablePath } else { '' })
        CommandLine = $(if ($details -and $details.CommandLine) { [string]$details.CommandLine } else { '' })
        CreateTime = $(if ($isStop) { '' } else { Convert-TraceTime $trace.TIME_CREATED })
        ExitTime = $(if ($isStop) { Convert-TraceTime $trace.TIME_CREATED } else { '' })
        Raw = @{
          collector = 'windows_etw_process'
          platform = 'windows_wmi_process_trace'
          source_class = $(if ($isStop) { 'Win32_ProcessStopTrace' } else { 'Win32_ProcessStartTrace' })
          process_name = [string]$trace.ProcessName
        }
      } | ConvertTo-Json -Compress
    }
    Remove-Event -EventIdentifier $event.EventIdentifier
  }
} finally {
  try { Unregister-Event -SourceIdentifier ShigureProcessStartTrace -ErrorAction SilentlyContinue } catch {}
  try { Unregister-Event -SourceIdentifier ShigureProcessStopTrace -ErrorAction SilentlyContinue } catch {}
}
`
