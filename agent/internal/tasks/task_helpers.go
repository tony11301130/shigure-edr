package tasks

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

func intArg(args map[string]any, key string, fallback int) int {
	v, ok := args[key]
	if !ok {
		return fallback
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		i, err := strconv.Atoi(t)
		if err == nil {
			return i
		}
	}
	return fallback
}

func boolArg(args map[string]any, key string, fallback bool) bool {
	v, ok := args[key]
	if !ok {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("command timed out")
	}
	return string(out), err
}
