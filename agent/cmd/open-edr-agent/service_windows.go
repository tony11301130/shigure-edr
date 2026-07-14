//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"
)

func installService(serviceName, displayName string, opts agentOptions, installDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(opts.StatePath), 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(opts.SpoolPath), 0700); err != nil {
		return fmt.Errorf("create spool dir: %w", err)
	}
	installedExe := filepath.Join(installDir, "shiori-agent.exe")
	if !samePath(exe, installedExe) {
		if err := copyExecutable(exe, installedExe); err != nil {
			return err
		}
	}
	args := []string{"--profile", opts.Profile, "--server", opts.Server, "--enroll-token", opts.EnrollToken, "--state", opts.StatePath, "--spool", opts.SpoolPath}
	if opts.ServerTrust != "" {
		args = append(args, "--server-trust", opts.ServerTrust)
	}
	binPath := windowsServiceCommandLine(installedExe, args)
	cmd := exec.Command("sc.exe", "create", serviceName, "binPath=", binPath, "DisplayName=", displayName, "start=", "auto")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create failed: %w: %s", err, string(out))
	}
	return nil
}

func uninstallService(serviceName string) error {
	cmd := exec.Command("sc.exe", "delete", serviceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete failed: %w: %s", err, string(out))
	}
	return nil
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		a, b = absA, absB
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source executable: %w", err)
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("create installed executable: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy installed executable: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close installed executable: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("replace installed executable: %w", err)
	}
	return nil
}

func runWindowsServiceIfNeeded(serviceName string, opts agentOptions) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, err
	}
	if !isService {
		return false, nil
	}
	return true, svc.Run(serviceName, &windowsService{opts: opts})
}

type windowsService struct {
	opts agentOptions
}

func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runAgent(s.opts, stop) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(stop)
				err := <-done
				if err != nil {
					return false, 1
				}
				return false, 0
			default:
				// Pause/continue and other controls are intentionally unsupported.
			}
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}
