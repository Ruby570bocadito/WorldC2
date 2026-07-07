//go:build linux || darwin

package agent

import (
	"os"
)

func openFile(path string) (*os.File, error) {
	return os.Open(path)
}
