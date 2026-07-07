package auth

import (
	"sync"
)

// RBAC defines role-based access control for C2 operations.
type RBAC struct {
	mu        sync.RWMutex
	roles     map[string]*Role
	roleUsers map[string][]string // role -> usernames
}

// Role defines a set of permissions.
type Role struct {
	Name        string
	Description string
	Permissions []string
}

// Predefined roles with granular permissions.
var (
	RoleAdmin = Role{
		Name:        "admin",
		Description: "Full access to all C2 operations",
		Permissions: []string{
			"sessions:list", "sessions:view", "sessions:kill",
			"commands:execute", "commands:broadcast",
			"modules:list", "modules:push", "modules:delete",
			"vault:create", "vault:read", "vault:delete",
			"files:upload", "files:download", "files:delete",
			"socks:start", "socks:stop",
			"portfwd:start", "portfwd:stop",
			"operators:create", "operators:read", "operators:delete",
			"audit:read",
		},
	}

	RoleOperator = Role{
		Name:        "operator",
		Description: "Standard operator - can execute commands and view sessions",
		Permissions: []string{
			"sessions:list", "sessions:view",
			"commands:execute", "commands:broadcast",
			"modules:list", "modules:push",
			"vault:create", "vault:read",
			"files:upload", "files:download",
			"socks:start", "socks:stop",
			"portfwd:start", "portfwd:stop",
		},
	}

	RoleViewer = Role{
		Name:        "viewer",
		Description: "Read-only access - can view sessions and logs",
		Permissions: []string{
			"sessions:list", "sessions:view",
			"modules:list",
			"vault:read",
			"files:download",
		},
	}

	RoleAuditor = Role{
		Name:        "auditor",
		Description: "Audit access - can view sessions, logs, and vault",
		Permissions: []string{
			"sessions:list", "sessions:view",
			"modules:list",
			"vault:read",
			"files:download",
			"audit:read",
		},
	}
)

// NewRBAC creates a new RBAC manager with predefined roles.
func NewRBAC() *RBAC {
	rbac := &RBAC{
		roles:     make(map[string]*Role),
		roleUsers: make(map[string][]string),
	}

	// Register predefined roles
	rbac.roles["admin"] = &RoleAdmin
	rbac.roles["operator"] = &RoleOperator
	rbac.roles["viewer"] = &RoleViewer
	rbac.roles["auditor"] = &RoleAuditor

	return rbac
}

// RegisterRole registers a custom role.
func (r *RBAC) RegisterRole(role *Role) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.Name] = role
}

// HasPermission checks if a role has a specific permission.
func (r *RBAC) HasPermission(roleName, permission string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	role, exists := r.roles[roleName]
	if !exists {
		return false
	}

	// Admin has all permissions
	if roleName == "admin" {
		return true
	}

	for _, p := range role.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// GetRole returns a role by name.
func (r *RBAC) GetRole(name string) *Role {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.roles[name]
}

// ListRoles returns all available roles.
func (r *RBAC) ListRoles() []Role {
	r.mu.RLock()
	defer r.mu.RUnlock()

	roles := make([]Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, *role)
	}
	return roles
}

// Permission constants for API endpoints.
const (
	PermSessionsList    = "sessions:list"
	PermSessionsView    = "sessions:view"
	PermSessionsKill    = "sessions:kill"
	PermCommandsExecute = "commands:execute"
	PermCommandsBroadcast = "commands:broadcast"
	PermModulesList     = "modules:list"
	PermModulesPush     = "modules:push"
	PermModulesDelete   = "modules:delete"
	PermVaultCreate     = "vault:create"
	PermVaultRead       = "vault:read"
	PermVaultDelete     = "vault:delete"
	PermFilesUpload     = "files:upload"
	PermFilesDownload   = "files:download"
	PermFilesDelete     = "files:delete"
	PermSocksStart      = "socks:start"
	PermSocksStop       = "socks:stop"
	PermPortFwdStart    = "portfwd:start"
	PermPortFwdStop     = "portfwd:stop"
	PermOperatorsCreate = "operators:create"
	PermOperatorsRead   = "operators:read"
	PermOperatorsDelete = "operators:delete"
	PermAuditRead       = "audit:read"
)
