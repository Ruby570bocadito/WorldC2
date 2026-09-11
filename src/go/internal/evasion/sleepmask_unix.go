//go:build linux || darwin

package evasion

import (
	"syscall"
	"unsafe"
)

// lockMemoryRegions changes memory protection from RWX to RX using mprotect.
// Region pointers are required to be page-aligned by MarkSensitive.
func (sm *SleepMask) lockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 || r.ptr == nil {
			continue
		}
		pageSize := syscall.Getpagesize()
		size := ((r.size + pageSize - 1) / pageSize) * pageSize
		if size <= 0 {
			continue
		}
		slice := unsafe.Slice((*byte)(r.ptr), size)
		syscall.Mprotect(slice, syscall.PROT_READ|syscall.PROT_EXEC)
	}
}

// unlockMemoryRegions changes memory protection from RX back to RWX.
func (sm *SleepMask) unlockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 || r.ptr == nil {
			continue
		}
		pageSize := syscall.Getpagesize()
		size := ((r.size + pageSize - 1) / pageSize) * pageSize
		if size <= 0 {
			continue
		}
		slice := unsafe.Slice((*byte)(r.ptr), size)
		syscall.Mprotect(slice, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	}
}
