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
          <button class="op-chip op-chip-btn" type="button" title="Account security" @click="openAccount">
            <span class="op-avatar">{{ initial }}</span>
            <span class="op-meta">
              <span class="op-name">{{ user || 'operator' }}</span>
              <span class="op-role">{{ role }}<span v-if="mfaEnabled" class="mfa-dot" title="TOTP MFA enabled"> · MFA</span></span>
            </span>
          </button>
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
            <button
              class="palette-hint"
              type="button"
              title="Jump to any view (Ctrl+K)"
              aria-label="Open command palette"
              @click="openPalette"
            >
              <IconSearch :size="13" />
              <span>Jump to…</span>
              <kbd>Ctrl K</kbd>
            </button>
          </div>

          <div class="server-state" :class="online ? 'is-online' : 'is-down'" :title="stateTitle">
            <span class="state-dot" />
            <span class="state-label">{{ online ? 'Server online' : 'Server unreachable' }}</span>
            <span v-if="online && version" class="state-version mono" :title="'Commit ' + (version.commit || 'unknown')">
              {{ version.version }}
            </span>
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

    <!-- command palette (Ctrl+K, r18): keyboard jump-to for every view the
         current role may open plus quick actions. Server-side guards stay
         authoritative — the palette only hides what the route table would
         refuse anyway. -->
    <div v-if="paletteOpen" class="palette-overlay" @click.self="closePalette">
      <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <input
          ref="paletteInput"
          v-model="paletteQuery"
          class="palette-input"
          type="text"
          placeholder="Jump to a view or action…"
          spellcheck="false"
          autocomplete="off"
          @keydown.esc.prevent="closePalette"
          @keydown.down.prevent="paletteMove(1)"
          @keydown.up.prevent="paletteMove(-1)"
          @keydown.enter.prevent="paletteRun()"
        />
        <ul v-if="paletteItems.length" class="palette-list">
          <li
            v-for="(item, i) in paletteItems"
            :key="item.id"
            class="palette-item"
            :class="{ 'is-active': i === paletteIndex }"
            @mousemove="paletteIndex = i"
            @click="paletteRun(item)"
          >
            <component :is="item.icon" :size="15" class="palette-icon" />
            <span class="palette-label">{{ item.label }}</span>
            <span class="palette-kind">{{ item.kind }}</span>
          </li>
        </ul>
        <p v-else class="palette-empty">No matches — Esc to close</p>
        <div class="palette-foot">
          <span><kbd>↑↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>

    <!-- Account security (r19): self-service password change + TOTP MFA
         enrollment for the CURRENT operator. Every action re-resolves the
         identity server-side from the auth headers. -->
    <div v-if="accountOpen" class="acct-overlay" @click.self="closeAccount">
      <div class="acct" role="dialog" aria-modal="true" aria-label="Account security">
        <div class="acct-head">
          <span class="acct-title">Account security</span>
          <button class="icon-btn" type="button" aria-label="Close" @click="closeAccount">
            <IconLogout :size="15" style="transform: rotate(90deg)" />
          </button>
        </div>

        <p v-if="acctNotice" class="acct-notice" role="status">{{ acctNotice }}</p>
        <p v-if="acctError" class="acct-error" role="alert">{{ acctError }}</p>

        <!-- password change -->
        <form class="acct-section" @submit.prevent="changePassword">
          <span class="acct-label">Change passphrase</span>
          <input
            v-model="pwForm.current"
            class="input mono"
            type="password"
            placeholder="Current passphrase"
            autocomplete="current-password"
            required
          />
          <input
            v-model="pwForm.next"
            class="input mono"
            type="password"
            placeholder="New passphrase (min 10 chars)"
            autocomplete="new-password"
            minlength="10"
            required
          />
          <input
            v-model="pwForm.confirm"
            class="input mono"
            type="password"
            placeholder="Repeat new passphrase"
            autocomplete="new-password"
            required
          />
          <button class="btn btn-primary" type="submit" :disabled="acctBusy">
            {{ acctBusy ? 'Working…' : 'Change passphrase' }}
          </button>
          <span class="acct-hint">Every session (including this one) is signed out after a change.</span>
        </form>

        <!-- TOTP MFA -->
        <div class="acct-section">
          <span class="acct-label">
            Two-factor authentication
            <span v-if="totp.enabled" class="badge badge-ok"><span class="dot dot-ok" /> enabled</span>
            <span v-else-if="totp.pending" class="badge">pending setup</span>
            <span v-else class="badge">disabled</span>
          </span>

          <template v-if="!totp.enabled && !totp.pending">
            <button class="btn btn-ghost" type="button" :disabled="acctBusy" @click="totpSetup">
              Set up authenticator app
            </button>
            <span class="acct-hint">Generates a secret your authenticator app (Aegis, Google Authenticator, 1Password…) stores as a 6-digit rolling code.</span>
          </template>

          <template v-if="totp.pending">
            <div class="totp-secret mono" :title="'Copy: ' + totp.secret" @click="copySecret">
              {{ totp.secret }}
            </div>
            <a class="totp-uri mono" :href="totp.uri" @click.prevent="copySecret">{{ totp.uri }}</a>
            <span class="acct-hint">Add the secret to your app, then confirm the current code. The secret is stored encrypted server-side and shown only now.</span>
            <input
              v-model="totp.code"
              class="input mono"
              type="text"
              inputmode="numeric"
              maxlength="6"
              placeholder="6-digit code"
              autocomplete="one-time-code"
            />
            <button class="btn btn-primary" type="button" :disabled="acctBusy || totp.code.length !== 6" @click="totpEnable">
              Confirm and enable
            </button>
          </template>

          <template v-if="totp.enabled">
            <span class="acct-hint">Each login will ask for the code from your authenticator app after the passphrase.</span>
            <input
              v-model="totp.code"
              class="input mono"
              type="text"
              inputmode="numeric"
              maxlength="6"
              placeholder="Current 6-digit code"
              autocomplete="one-time-code"
            />
            <button class="btn btn-ghost" type="button" :disabled="acctBusy || totp.code.length !== 6" @click="totpDisable">
              Disable two-factor
            </button>
          </template>
        </div>
      </div>
    </div>
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
  IconProfiles,
  IconWebhook,
  IconOperators,
  IconAudit,
  IconKey,
  IconLogout,
  IconMenu,
  IconSearch,
} from './components/icons.js'
import { api } from './utils/api.js'

const NAV = [
  { to: '/', label: 'Dashboard', icon: IconDashboard, exact: true },
  { to: '/sessions', label: 'Sessions', icon: IconSessions },
  { to: '/terminal', label: 'Command Runner', icon: IconTerminal },
  { to: '/modules', label: 'Modules', icon: IconModules },
  { to: '/profiles', label: 'Profiles', icon: IconProfiles },
  { to: '/files', label: 'Files', icon: IconFiles },
  { to: '/vault', label: 'Vault', icon: IconKey },
  { to: '/webhooks', label: 'Webhooks', icon: IconWebhook },
  { to: '/audit', label: 'Audit log', icon: IconAudit },
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
    IconProfiles,
    IconWebhook,
    IconOperators,
    IconAudit,
    IconKey,
    IconLogout,
    IconMenu,
    IconSearch,
  },
  data() {
    return {
      navItems: NAV,
      authed: !!localStorage.getItem('bty_token'),
      sidebarOpen: false,
      online: true,
      health: { active_sessions: 0, listeners: 0 },
      timer: null,
      // Command palette (r18): open state, query text and active row.
      paletteOpen: false,
      paletteQuery: '',
      paletteIndex: 0,
      // Account security (r19): modal state + the two forms.
      accountOpen: false,
      acctBusy: false,
      acctNotice: '',
      acctError: '',
      pwForm: { current: '', next: '', confirm: '' },
      totp: { enabled: false, pending: false, secret: '', uri: '', code: '' },
      mfaEnabled: false,
      // Server identity (r19): fetched on a slow cadence — the version
      // chip does not justify a heavy /api/status every 5 s.
      version: null,
      versionTimer: null,
      // Idle auto-logout (r19): last user-activity timestamp + the
      // watchdog interval handle.
      lastActivity: Date.now(),
      idleTimer: null,
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
    // Palette entries: every view the current ROLE may open (mirroring the
    // route table's requiresAdmin / roles metadata — the server-side guards
    // stay the real gate) plus the logout action. Substring filter on the
    // query, case-insensitive.
    paletteItems() {
      const role = this.role
      const views = NAV.filter((item) => {
        if (item.to === '/webhooks' || item.to === '/operators') return role === 'admin'
        if (item.to === '/audit') return role === 'admin' || role === 'auditor'
        return true
      }).map((item) => ({ id: 'go:' + item.to, label: item.label, kind: 'view', icon: item.icon, to: item.to }))
      const actions = [
        { id: 'act:logout', label: 'Logout', kind: 'action', icon: IconLogout, run: 'logout' },
      ]
      const all = views.concat(actions)
      const q = this.paletteQuery.trim().toLowerCase()
      if (!q) return all
      return all.filter((item) => item.label.toLowerCase().includes(q))
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
        this.startIdleWatch()
      } else {
        this.stopPolling()
        this.stopIdleWatch()
      }
    },
  },
  mounted() {
    if (this.authed) {
      this.fetchHealth()
      this.startPolling()
      this.fetchVersion()
      this.startIdleWatch()
    }
    window.addEventListener('keydown', this.onGlobalKeydown)
    window.addEventListener('pointerdown', this.onUserActivity)
    window.addEventListener('keydown', this.onUserActivity)
    window.addEventListener('wheel', this.onUserActivity)
  },
  beforeUnmount() {
    this.stopPolling()
    this.stopIdleWatch()
    if (this.versionTimer) clearInterval(this.versionTimer)
    window.removeEventListener('keydown', this.onGlobalKeydown)
    window.removeEventListener('pointerdown', this.onUserActivity)
    window.removeEventListener('keydown', this.onUserActivity)
    window.removeEventListener('wheel', this.onUserActivity)
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
    // Global shortcut: Ctrl+K / Cmd+K toggles the palette. Guarded by
    // authed — the palette is meaningless on the login screen (and the
    // shortcut would fight the login form's own focus handling).
    onGlobalKeydown(e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        if (!this.authed) return
        this.paletteOpen ? this.closePalette() : this.openPalette()
      }
    },
    openPalette() {
      this.paletteQuery = ''
      this.paletteIndex = 0
      this.paletteOpen = true
      // Focus after the dialog renders (v-if is async on paint).
      this.$nextTick(() => {
        if (this.$refs.paletteInput) this.$refs.paletteInput.focus()
      })
    },
    closePalette() {
      this.paletteOpen = false
    },
    paletteMove(dir) {
      const n = this.paletteItems.length
      if (!n) return
      this.paletteIndex = (this.paletteIndex + dir + n) % n
    },
    paletteRun(item) {
      const entry = item || this.paletteItems[this.paletteIndex]
      if (!entry) return
      this.closePalette()
      if (entry.run === 'logout') {
        this.logout()
        return
      }
      if (entry.to && this.$route.path !== entry.to) this.$router.push(entry.to)
    },
    logout() {
      ;['bty_token', 'bty_refresh', 'bty_expires', 'bty_user', 'bty_role'].forEach((k) =>
        localStorage.removeItem(k)
      )
      this.stopPolling()
      this.authed = false
      this.$router.push('/login')
    },

    // ---------- account security (r19) ----------
    openAccount() {
      this.acctNotice = ''
      this.acctError = ''
      this.pwForm = { current: '', next: '', confirm: '' }
      this.totp = { enabled: false, pending: false, secret: '', uri: '', code: '' }
      this.accountOpen = true
      this.fetchTotpStatus()
    },
    closeAccount() {
      this.accountOpen = false
    },
    async fetchTotpStatus() {
      try {
        const st = await api.get('/api/account/totp/status')
        this.totp.enabled = !!st.enabled
        this.totp.pending = !!st.pending
        this.mfaEnabled = !!st.enabled
      } catch {
        /* the panel degrades to "unknown" silently — non-fatal */
      }
    },
    async changePassword() {
      if (this.acctBusy) return
      if (this.pwForm.next !== this.pwForm.confirm) {
        this.acctError = 'The two new passphrases do not match'
        return
      }
      this.acctBusy = true
      this.acctError = ''
      this.acctNotice = ''
      try {
        await api.post('/api/account/password', {
          current_password: this.pwForm.current,
          new_password: this.pwForm.next,
        })
        // The server revoked every token for this user: force a clean
        // re-login with the new passphrase (full navigation drops SPA
        // state, matching the api.js expired-session behavior).
        alert('Passphrase changed. Please sign in again.')
        window.location.assign('/login')
      } catch (e) {
        this.acctError = e.message || 'Change failed'
      } finally {
        this.acctBusy = false
      }
    },
    async totpSetup() {
      if (this.acctBusy) return
      this.acctBusy = true
      this.acctError = ''
      try {
        const st = await api.post('/api/account/totp/setup', {})
        this.totp.secret = st.secret || ''
        this.totp.uri = st.otpauth_uri || ''
        this.totp.pending = true
        this.totp.code = ''
      } catch (e) {
        this.acctError = e.message || 'Setup failed'
      } finally {
        this.acctBusy = false
      }
    },
    async totpEnable() {
      if (this.acctBusy || this.totp.code.length !== 6) return
      this.acctBusy = true
      this.acctError = ''
      try {
        await api.post('/api/account/totp/enable', { code: this.totp.code.trim() })
        this.totp.enabled = true
        this.totp.pending = false
        this.totp.secret = ''
        this.totp.uri = ''
        this.mfaEnabled = true
        this.acctNotice = 'Two-factor authentication enabled.'
      } catch (e) {
        this.acctError = e.message || 'Enable failed'
      } finally {
        this.acctBusy = false
      }
    },
    async totpDisable() {
      if (this.acctBusy || this.totp.code.length !== 6) return
      this.acctBusy = true
      this.acctError = ''
      try {
        await api.post('/api/account/totp/disable', { code: this.totp.code.trim() })
        this.totp.enabled = false
        this.totp.pending = false
        this.totp.code = ''
        this.mfaEnabled = false
        this.acctNotice = 'Two-factor authentication disabled.'
      } catch (e) {
        this.acctError = e.message || 'Disable failed'
      } finally {
        this.acctBusy = false
      }
    },
    copySecret() {
      if (this.totp.secret) navigator.clipboard?.writeText(this.totp.secret).catch(() => {})
    },

    // ---------- server identity chip (r19) ----------
    async fetchVersion() {
      if (!this.authed) return
      try {
        const st = await api.get('/api/status')
        this.version = st && st.version ? { version: st.version, commit: st.commit } : null
      } catch {
        /* a failed status fetch keeps the previous chip value */
      }
      if (!this.versionTimer) {
        this.versionTimer = setInterval(() => this.fetchVersion(), 60000)
      }
    },

    // ---------- idle auto-logout (r19) ----------
    onUserActivity() {
      this.lastActivity = Date.now()
    },
    startIdleWatch() {
      if (this.idleTimer) return
      this.lastActivity = Date.now()
      // Check every 30 s; 15 min of NO user interaction closes the
      // session. Server polls (health/status) do NOT count as activity —
      // they are this.onUserActivity-blind by construction because they
      // fire no DOM events. Client-side only by design: it shrinks the
      // exposed-console window; the JWT's own TTL stays the hard limit.
      this.idleTimer = setInterval(() => {
        if (!this.authed) return
        if (Date.now() - this.lastActivity > 15 * 60 * 1000) {
          ;['bty_token', 'bty_refresh', 'bty_expires', 'bty_user', 'bty_role'].forEach((k) =>
            localStorage.removeItem(k)
          )
          this.stopPolling()
          this.stopIdleWatch()
          this.authed = false
          window.location.assign('/login?idle=1')
        }
      }, 30000)
    },
    stopIdleWatch() {
      if (this.idleTimer) {
        clearInterval(this.idleTimer)
        this.idleTimer = null
      }
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

/* clickable account chip (r19) */
.op-chip-btn {
  cursor: pointer;
  text-align: left;
  font: inherit;
  color: inherit;
  transition: border-color var(--speed), background var(--speed);
}
.op-chip-btn:hover { border-color: rgba(110, 123, 242, 0.4); }
.mfa-dot { color: var(--ok); font-weight: 600; }

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

/* topbar palette hint — makes the shortcut discoverable (and clickable) */
.palette-hint {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  margin-left: 14px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--muted);
  font-size: 12px;
  cursor: pointer;
  transition: color var(--speed), border-color var(--speed);
}
.palette-hint:hover { color: var(--text); border-color: var(--border-strong, var(--border)); }
.palette-hint kbd {
  font-family: var(--mono);
  font-size: 10.5px;
  padding: 1px 5px;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: var(--surface-2);
  color: var(--muted);
}

/* ---------- command palette ---------- */
.palette-overlay {
  position: fixed;
  inset: 0;
  z-index: 90;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 12vh 16px 16px;
}
.palette {
  width: 100%;
  max-width: 480px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius, 10px);
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.55);
  overflow: hidden;
}
.palette-input {
  width: 100%;
  height: 46px;
  padding: 0 16px;
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--border-soft);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
  outline: none;
}
.palette-input::placeholder { color: var(--faint); }
.palette-list {
  list-style: none;
  margin: 0;
  padding: 6px;
  max-height: 320px;
  overflow-y: auto;
}
.palette-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px;
  border-radius: var(--radius-sm, 6px);
  color: var(--muted);
  font-size: 13.5px;
  cursor: pointer;
}
.palette-item.is-active {
  background: var(--accent-soft);
  color: var(--text);
}
.palette-item.is-active .palette-icon { color: var(--accent); }
.palette-label { flex: 1; }
.palette-kind {
  font-size: 10.5px;
  font-family: var(--mono);
  color: var(--faint);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.palette-empty {
  margin: 0;
  padding: 18px 16px;
  color: var(--faint);
  font-size: 13px;
}
.palette-foot {
  display: flex;
  gap: 16px;
  padding: 8px 12px;
  border-top: 1px solid var(--border-soft);
  color: var(--faint);
  font-size: 11px;
}
.palette-foot kbd {
  font-family: var(--mono);
  font-size: 10px;
  padding: 1px 4px;
  border-radius: 3px;
  border: 1px solid var(--border);
  background: var(--surface-2);
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
.state-version {
  color: var(--accent);
  font-size: 11.5px;
  padding: 1px 7px;
  border: 1px solid rgba(110, 123, 242, 0.35);
  border-radius: 999px;
  background: var(--accent-soft);
}
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

/* ---------- account security modal (r19) ---------- */
.acct-overlay {
  position: fixed;
  inset: 0;
  z-index: 90;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 10vh 16px 16px;
}
.acct {
  width: 100%;
  max-width: 420px;
  max-height: 80vh;
  overflow-y: auto;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius, 10px);
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.55);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.acct-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.acct-title {
  font-family: var(--mono);
  font-weight: 700;
  font-size: 15px;
}
.acct-section {
  display: flex;
  flex-direction: column;
  gap: 9px;
  padding: 12px;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  background: var(--surface-2);
}
.acct-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--muted);
}
.acct-hint {
  font-size: 11.5px;
  color: var(--faint);
  line-height: 1.45;
}
.acct-notice {
  margin: 0;
  font-size: 12.5px;
  color: var(--ok);
  background: rgba(63, 182, 139, 0.08);
  border: 1px solid rgba(63, 182, 139, 0.35);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
}
.acct-error {
  margin: 0;
  font-size: 12.5px;
  color: var(--danger);
  background: var(--danger-soft);
  border: 1px solid rgba(229, 72, 77, 0.35);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
}
.totp-secret {
  font-size: 15px;
  letter-spacing: 0.08em;
  word-break: break-all;
  padding: 9px 10px;
  border: 1px dashed var(--border);
  border-radius: var(--radius-sm);
  background: var(--surface);
  cursor: pointer;
  user-select: all;
}
.totp-uri {
  font-size: 10.5px;
  color: var(--faint);
  word-break: break-all;
  cursor: pointer;
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
