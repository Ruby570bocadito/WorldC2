//go:build !windows

package agent

import "os"

func isAdmin() bool {
	return os.Geteuid() == 0
}
