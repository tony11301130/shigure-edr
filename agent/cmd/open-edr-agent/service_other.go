//go:build !windows

package main

import "fmt"

func installService(serviceName, displayName string, opts agentOptions, installDir string, binaryName string) error {
	return fmt.Errorf("service installation is only supported on Windows")
}

func uninstallService(serviceName string) error {
	return fmt.Errorf("service uninstallation is only supported on Windows")
}

func runWindowsServiceIfNeeded(serviceName string, opts agentOptions) (bool, error) {
	return false, nil
}
