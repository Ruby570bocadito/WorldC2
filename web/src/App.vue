<template>
  <div class="app">
    <header class="header" v-if="isAuthed">
      <div class="header-left">
        <router-link to="/" class="logo">WORLDC2</router-link>
        <nav class="nav">
          <router-link to="/" class="nav-item" :class="{active:$route.path==='/'}">Dashboard</router-link>
          <router-link to="/sessions" class="nav-item" :class="{active:$route.path.startsWith('/sessions')}">Victims</router-link>
          <router-link to="/terminal" class="nav-item" :class="{active:$route.path==='/terminal'}">Terminal</router-link>
          <router-link to="/modules" class="nav-item" :class="{active:$route.path==='/modules'}">Modules</router-link>
          <router-link to="/files" class="nav-item" :class="{active:$route.path==='/files'}">Files</router-link>
          <router-link to="/operators" class="nav-item" :class="{active:$route.path==='/operators'}">Operators</router-link>
        </nav>
      </div>
      <div class="header-right">
        <span v-if="connectionError" class="error-indicator" title="Connection lost">●</span>
        <template v-else>
          <span class="online-dot"></span>
          <span class="online-count">{{ status.sessions || 0 }}</span>
        </template>
        <span class="uptime" v-if="status.uptime">{{ formatUptime(status.uptime) }}</span>
        <span class="user-badge">{{ user }} ({{ role }})</span>
        <button @click="logout" class="logout-btn">Logout</button>
      </div>
    </header>
    <main>
      <div v-if="loading" class="loading-overlay">
        <div class="spinner"></div>
        <p>Loading...</p>
      </div>
      <div v-else-if="connectionError" class="error-banner">
        <p>⚠ Connection to C2 server lost. Retrying...</p>
        <button @click="retryConnection" class="retry-btn">Retry Now</button>
      </div>
      <router-view v-else />
    </main>
  </div>
</template>

<script>
export default {
  data() {
    return {
      status: {},
      timer: null,
      loading: true,
      connectionError: false,
      retryCount: 0,
      maxRetries: 10,
      user: '',
      role: ''
    }
  },
  computed: {
    isAuthed() { return !!sessionStorage.getItem('bty_token') }
  },
  mounted() {
    this.user = sessionStorage.getItem('bty_user') || ''
    this.role = sessionStorage.getItem('bty_role') || ''
    if (this.isAuthed) {
      this.fetch()
      this.timer = setInterval(() => this.fetch(), 5000)
    } else {
      this.loading = false
    }
  },
  beforeUnmount() { clearInterval(this.timer) },
  methods: {
    auth() {
      const t = sessionStorage.getItem('bty_token')
      return t ? { Authorization: 'Bearer ' + t } : {}
    },
    async fetch() {
      try {
        const r = await fetch('/api/health', {
          headers: this.auth(),
          signal: AbortSignal.timeout(5000)
        })
        if (!r.ok) {
          throw new Error(`HTTP ${r.status}`)
        }
        this.status = await r.json()
        if (this.connectionError) {
          this.connectionError = false
          this.retryCount = 0
        }
        this.loading = false
      } catch (e) {
        console.error('Health check failed:', e)
        this.connectionError = true
        this.loading = false
        this.retryCount++

        if (this.retryCount >= this.maxRetries) {
          clearInterval(this.timer)
          setTimeout(() => {
            this.timer = setInterval(() => this.fetch(), 5000)
            this.retryCount = 0
          }, 30000)
        }
      }
    },
    async retryConnection() {
      this.retryCount = 0
      this.loading = true
      await this.fetch()
    },
    formatUptime(ts) {
      const diff = Date.now() / 1000 - ts
      const hours = Math.floor(diff / 3600)
      const mins = Math.floor((diff % 3600) / 60)
      if (hours > 0) return `${hours}h ${mins}m`
      return `${mins}m`
    },
    logout() {
      sessionStorage.removeItem('bty_token')
      sessionStorage.removeItem('bty_refresh')
      sessionStorage.removeItem('bty_user')
      sessionStorage.removeItem('bty_role')
      sessionStorage.removeItem('bty_expires')
      clearInterval(this.timer)
      this.$router.push('/login')
    }
  }
}
</script>

<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#f8f9fa;color:#1a1a2e}
.app{min-height:100vh;display:flex;flex-direction:column}
.header{display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:56px;background:#fff;border-bottom:1px solid #e5e7eb;position:sticky;top:0;z-index:100}
.header-left{display:flex;align-items:center;gap:32px}
.logo{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;color:#059669;text-decoration:none;letter-spacing:-1px}
.nav{display:flex;gap:4px}
.nav-item{padding:6px 14px;border-radius:6px;font-size:13px;font-weight:500;color:#6b7280;text-decoration:none;transition:all .15s}
.nav-item:hover{background:#f3f4f6;color:#1f2937}
.nav-item.active{background:#ecfdf5;color:#059669;font-weight:600}
.header-right{display:flex;align-items:center;gap:12px}
.online-dot{width:8px;height:8px;border-radius:50%;background:#10b981;animation:pulse 2s infinite}
.online-count{font-size:13px;color:#6b7280;font-family:'JetBrains Mono',monospace}
.uptime{font-size:12px;color:#9ca3af;font-family:'JetBrains Mono',monospace}
.user-badge{font-size:12px;color:#6b7280;font-family:'JetBrains Mono',monospace;background:#f3f4f6;padding:3px 10px;border-radius:6px}
.error-indicator{width:8px;height:8px;border-radius:50%;background:#ef4444;animation:pulse-error 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes pulse-error{0%,100%{opacity:1}50%{opacity:.2}}
.logout-btn{font-size:12px;color:#9ca3af;background:none;border:1px solid #e5e7eb;padding:4px 12px;border-radius:6px;cursor:pointer}
.logout-btn:hover{color:#ef4444;border-color:#fecaca}
main{flex:1;padding:24px;max-width:1280px;width:100%;margin:0 auto}

.loading-overlay{display:flex;flex-direction:column;align-items:center;justify-content:center;height:60vh;gap:16px}
.spinner{width:40px;height:40px;border:3px solid #e5e7eb;border-top-color:#059669;border-radius:50%;animation:spin 0.8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-overlay p{color:#6b7280;font-size:14px}

.error-banner{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px 24px;text-align:center;margin:20px 0}
.error-banner p{color:#dc2626;font-size:14px;margin-bottom:12px}
.retry-btn{background:#dc2626;color:#fff;border:none;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500}
.retry-btn:hover{background:#b91c1c}
</style>
