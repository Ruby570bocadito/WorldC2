package auth

import "testing"

// TestCollabReadIsUniversal pins the round 9 RBAC contract: session notes and
// config profiles are READABLE by every role (collab:read) while only
// admin/operator can WRITE them (collab:write). Before this, GET /api/notes
// demanded collab:write — so the read-only roles (viewer, auditor) could read
// captured credentials (vault:read) but not the operator notes an auditor
// exists to review. If a future edit drops collab:read from any role, this
// test fails before the regression ships.
func TestCollabReadIsUniversal(t *testing.T) {
	rbac := NewRBAC()
	for _, roleName := range predefinedRoleNames {
		if rbac.GetRole(roleName) == nil {
			t.Fatalf("role %s not registered", roleName)
		}
		if !rbac.HasPermission(roleName, PermCollabRead) {
			t.Errorf("role %s lacks %s — read-only roles must be able to view notes/profiles", roleName, PermCollabRead)
		}
	}
}

// TestCollabWriteStaysPrivileged makes sure the universal read did not leak
// into the write side: viewer and auditor must NOT gain collab:write.
func TestCollabWriteStaysPrivileged(t *testing.T) {
	rbac := NewRBAC()
	for _, roleName := range []string{"viewer", "auditor"} {
		if rbac.HasPermission(roleName, PermCollabWrite) {
			t.Errorf("role %s unexpectedly has %s", roleName, PermCollabWrite)
		}
	}
	for _, roleName := range []string{"admin", "operator"} {
		if !rbac.HasPermission(roleName, PermCollabWrite) {
			t.Errorf("role %s lost %s", roleName, PermCollabWrite)
		}
	}
}
