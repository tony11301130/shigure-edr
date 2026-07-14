//go:build !linux && !windows

package collect

import "runtime"

func hostBootID() string {
	return runtime.GOOS + "_boot_id_unavailable"
}
