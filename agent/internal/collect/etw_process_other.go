//go:build !windows

package collect

import "context"

func startPlatformETWProcessSource(ctx context.Context, collector *ETWProcessCollector) error {
	return nil
}
