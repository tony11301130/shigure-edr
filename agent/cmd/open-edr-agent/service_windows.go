//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/svc"
)

func installService(serviceName, displayName, server, enrollToken, statePath, spoolPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"--server", server, "--enroll-token", enrollToken, "--state", statePath, "--spool", spoolPath}
	binPath := fmt.Sprintf("\"%s\" %s", exe, strings.Join(args, " "))
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
