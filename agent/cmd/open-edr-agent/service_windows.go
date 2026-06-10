//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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
