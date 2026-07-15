//go:build !windows

package collect

import "context"

func startPlatformWindowsEventLogSource(ctx context.Context, subscriber *WindowsEventLogSubscriber) error {
	return nil
}
