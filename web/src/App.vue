<template>
  <div class="app-shell">
    <template v-if="authed">
      <!-- sidebar -->
      <aside class="sidebar" :class="{ open: sidebarOpen }">
        <router-link to="/" class="brand">
          <IconShield :size="22" class="brand-icon" />
          <span class="brand-name">WorldC2</span>
        </router-link>

        <nav class="nav" aria-label="Primary">
          <router-link
            v-for="item in navItems"
            :key="item.to"
            :to="item.to"
            class="nav-link"
            :class="{ 'is-active': isActive(item) }"
            @click="closeSidebar"
          >
            <component :is="item.icon" :size="18" />
            <span>{{ item.label }}</span>
          </router-link>
        </nav>

        <div class="sidebar-foot">
          <div class="op-chip">
            <span class="op-avatar">{{ initial }}</span>
            <span class="op-meta">
              <span class="op-name">{{ user || 'operator' }}</span>
              <span class="op-role">{{ role }}</span>
            </span>
          </div>
          <button class="btn btn-ghost btn-sm logout" type="button" @click="logout">
            <IconLogout :size="15" />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      <div v-if="sidebarOpen" class="backdrop" @click="closeSidebar" />

      <!-- main column -->
      <div class="main-col">
        <header class="topbar">
          <div class="topbar-left">
            <button
              class="icon-btn menu-btn"
              type="button"
              aria-label="Toggle navigation"
              @click="sidebarOpen = !sidebarOpen"
            >
              <IconMenu :size="18" />
            </button>
            <span class="crumb">{{ pageTitle }}</span>
          </div>

          <div class="server-state" :class="online ? 'is-online' : 'is-down'" :title="stateTitle">
            <span class="state-dot" />
            <span class="state-label">{{ online ? 'Server online' : 'Server unreachable' }}</span>
            <span v-if="online" class="state-meta mono">
              {{ health.active_sessions }} sess · {{ health.listeners }} listeners
            </span>
          </div>
        </header>

        <main class="content">
          <router-view />
        </main>
      </div>
    </template>

    <!-- bare layout (login) -->
    <template v-else>
      <router-view />
    </template>
  </div>
</template>

<script>
import {
  IconShield,
  IconDashboard,
  IconSessions,
  IconTerminal,
  IconFiles,
  IconModules,
  IconOperators,
  IconLogout,
  IconMenu,
} from './components/icons.js'
import { api } from './utils/api.js'

const NAV = [
  { to: '/', label: 'Dashboard', icon: IconDashboard, exact: true },
  { to: '/sessions', label: 'Sessions', icon: IconSessions },
  { to: '/terminal', label: 'Command Runner', icon: IconTerminal },
  { to: '/modules', label: 'Modules', icon: IconModules },
  { to: '/files', label: 'Files', icon: IconFiles },
  { to: '/operators', label: 'Operators', icon: IconOperators },
]

export default {
  name: 'App',
  components: {
    IconShield,
    IconDashboard,
    IconSessions,
    IconTerminal,
    IconFiles,
    IconModules,
    IconOperators,
    IconLogout,
    IconMenu,
  },
  data() {
    return {
      navItems: NAV,
      authed: !!localStorage.getItem('bty_token'),
      sidebarOpen: false,
      online: true,
      health: { active_sessions: 0, listeners: 0 },
      timer: null,
    }
  },
  computed: {
    user() {
      return localStorage.getItem('bty_user') || ''
    },
    role() {
      return localStorage.getItem('bty_role') || 'operator'
    },
    initial() {
      return (localStorage.getItem('bty_user') || '?').charAt(0).toUpperCase()
    },
    pageTitle() {
      return this.$route.meta.title || ''
    },
    stateTitle() {
      if (!this.online) return 'Last health check failed'
      return 'Active sessions: ' + this.health.active_sessions
    },
  },
  watch: {
    // localStorage is not reactive — re-evaluate on every navigation
    $route() {
      this.authed = !!localStorage.getItem('bty_token')
      if (this.authed) {
        // Refresh immediately so the topbar never shows stale zeros for
        // the first polling interval after login.
        this.fetchHealth()
        this.startPolling()
      } else {
        this.stopPolling()
      }
    },
  },
  mounted() {
    if (this.authed) {
      this.fetchHealth()
      this.startPolling()
    }
  },
  beforeUnmount() {
    this.stopPolling()
  },
  methods: {
    isActive(item) {
      return item.exact ? this.$route.path === item.to : this.$route.path.startsWith(item.to)
    },
    startPolling() {
      if (this.timer) return
      this.timer = setInterval(() => this.fetchHealth(), 5000)
    },
    stopPolling() {
      if (this.timer) {
        clearInterval(this.timer)
        this.timer = null
      }
    },
    async fetchHealth() {
      try {
        const data = await api.get('/api/health')
        this.health = data && typeof data === 'object' ? data : {}
        this.online = true
      } catch {
        this.online = false
      }
    },
    closeSidebar() {
      this.sidebarOpen = false
    },
    logout() {
      ;['bty_token', 'bty_refresh', 'bty_expires', 'bty_user', 'bty_role'].forEach((k) =>
        localStorage.removeItem(k)
      )
      this.stopPolling()
      this.authed = false
      this.$router.push('/login')
    },
  },
}
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  display: flex;
}

/* ---------- sidebar ---------- */
.sidebar {
  position: fixed;
  top: 0;
  bottom: 0;
  left: 0;
  width: 230px;
  display: flex;
  flex-direction: column;
  background: var(--surface);
  border-right: 1px solid var(--border);
  z-index: 60;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 56px;
  padding: 0 20px;
  border-bottom: 1px solid var(--border-soft);
  color: var(--text);
  flex-shrink: 0;
}
.brand:hover { color: var(--text); }
.brand-icon { color: var(--accent); }
.brand-name {
  font-family: var(--mono);
  font-weight: 700;
  font-size: 16px;
  letter-spacing: -0.02em;
}

.nav {
  flex: 1;
  padding: 14px 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  overflow-y: auto;
}
.nav-link {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 9px 12px;
  border-radius: var(--radius-sm);
  color: var(--muted);
  font-size: 13.5px;
  border: 1px solid transparent;
  transition: color var(--speed), background var(--speed), border-color var(--speed);
}
.nav-link:hover { color: var(--text); background: var(--surface-2); }
.nav-link.is-active {
  color: var(--text);
  background: var(--accent-soft);
  border-color: rgba(110, 123, 242, 0.28);
}
.nav-link.is-active .icon { color: var(--accent); }

.sidebar-foot {
  padding: 12px;
  border-top: 1px solid var(--border-soft);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.op-chip {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  background: var(--surface-2);
  border: 1px solid var(--border-soft);
  min-width: 0;
}
.op-avatar {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid rgba(110, 123, 242, 0.35);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 600;
  flex-shrink: 0;
}
.op-meta {
  display: flex;
  flex-direction: column;
  line-height: 1.25;
  min-width: 0;
}
.op-name {
  font-size: 13px;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.op-role {
  font-size: 11px;
  color: var(--muted);
  font-family: var(--mono);
}
.logout { justify-content: flex-start; }

.backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  z-index: 55;
}

/* ---------- main column ---------- */
.main-col {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  margin-left: 230px;
  min-height: 100vh;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 50;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 0 24px;
  background: rgba(11, 12, 15, 0.82);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
}
.topbar-left {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.menu-btn { display: none; }
.crumb {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
  letter-spacing: 0.02em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.server-state {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
  padding: 5px 12px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  white-space: nowrap;
}
.state-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--faint);
  flex-shrink: 0;
}
.server-state.is-online { color: var(--muted); }
.server-state.is-online .state-dot {
  background: var(--ok);
  box-shadow: 0 0 6px rgba(63, 182, 139, 0.55);
  animation: breathe 2.4s ease-in-out infinite;
}
.server-state.is-down { color: var(--danger); }
.server-state.is-down .state-dot {
  background: var(--danger);
  box-shadow: 0 0 6px rgba(229, 72, 77, 0.55);
}
.state-meta { color: var(--faint); font-size: 11.5px; }
@keyframes breathe {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.45; }
}

.content {
  flex: 1;
  width: 100%;
  max-width: 1280px;
  margin: 0 auto;
  padding: 28px 32px 48px;
}

/* ---------- responsive ---------- */
@media (max-width: 900px) {
  .sidebar {
    transform: translateX(-100%);
    transition: transform 180ms ease;
    box-shadow: 0 0 40px rgba(0, 0, 0, 0.5);
  }
  .sidebar.open { transform: translateX(0); }
  .main-col { margin-left: 0; }
  .menu-btn { display: inline-flex; }
  .content { padding: 20px 16px 40px; }
  .state-meta { display: none; }
}
</style>
