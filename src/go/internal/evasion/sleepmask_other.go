//go:build !linux && !darwin && !windows

package evasion

// lockMemoryRegions is a no-op on unsupported platforms.
func (sm *SleepMask) lockMemoryRegions() {}

// unlockMemoryRegions is a no-op on unsupported platforms.
func (sm *SleepMask) unlockMemoryRegions() {}
