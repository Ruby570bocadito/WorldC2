//go:build !windows

package evasion

// ETWBypassResult contains the result of an ETW bypass attempt.
type ETWBypassResult struct {
	Success bool
	Method  int
	Error   string
	Note    string
}

// PatchEtwEventWrite is a no-op on non-Windows.
func PatchEtwEventWrite() *ETWBypassResult {
	return &ETWBypassResult{Success: false, Note: "ETW is Windows-only"}
}

// PatchEtwEventWriteFull is a no-op on non-Windows.
func PatchEtwEventWriteFull() *ETWBypassResult {
	return &ETWBypassResult{Success: false, Note: "ETW is Windows-only"}
}

// PatchEtwEventWriteEx is a no-op on non-Windows.
func PatchEtwEventWriteEx() *ETWBypassResult {
	return &ETWBypassResult{Success: false, Note: "ETW is Windows-only"}
}

// PatchEtwEventWriteTransfer is a no-op on non-Windows.
func PatchEtwEventWriteTransfer() *ETWBypassResult {
	return &ETWBypassResult{Success: false, Note: "ETW is Windows-only"}
}

// PatchEtwEventWriteString is a no-op on non-Windows.
func PatchEtwEventWriteString() *ETWBypassResult {
	return &ETWBypassResult{Success: false, Note: "ETW is Windows-only"}
}

// PatchAllETW patches all ETW functions (no-op on non-Windows).
func PatchAllETW() []ETWBypassResult {
	return []ETWBypassResult{{Success: false, Note: "ETW is Windows-only"}}
}

// CheckETWStatus always returns all false on non-Windows.
func CheckETWStatus() map[string]bool {
	return map[string]bool{"EtwEventWrite": false}
}

// IsETWEnabled always returns true on non-Windows.
func IsETWEnabled() bool { return true }
