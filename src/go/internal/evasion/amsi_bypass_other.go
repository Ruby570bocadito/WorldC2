//go:build !windows

package evasion

// AMSIBypassResult contains the result of an AMSI bypass attempt.
type AMSIBypassResult struct {
	Success bool
	Method  string
	Error   string
	Note    string
}

// PatchAmsiInMemory is a no-op on non-Windows.
func PatchAmsiInMemory() *AMSIResult {
	return &AMSIResult{Success: false, Method: "patch", Note: "AMSI is Windows-only"}
}

// PatchAmsiScanString is a no-op on non-Windows.
func PatchAmsiScanString() *AMSIResult {
	return &AMSIResult{Success: false, Method: "patch_string", Note: "AMSI is Windows-only"}
}

// PatchAmsiInitialize is a no-op on non-Windows.
func PatchAmsiInitialize() *AMSIResult {
	return &AMSIResult{Success: false, Method: "patch_init", Note: "AMSI is Windows-only"}
}

// CheckAMSIStatus always returns true on non-Windows.
func CheckAMSIStatus() bool { return true }

// AMSIResult contains the result of an AMSI operation.
type AMSIResult struct {
	Success bool
	Method  string
	Error   string
	Note    string
}
