<template>
  <div class="dashboard-page">
    <!-- Header -->
    <div class="dash-header">
      <div>
        <h1 class="dash-title">DASHBOARD</h1>
        <p class="dash-subtitle">Real-time operational overview</p>
      </div>
      <div class="live-indicator">
        <span class="live-dot"></span>
        LIVE
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="stats-grid">
      <div class="stat-card stat-green">
        <div class="stat-value">{{ sessions.length }}</div>
        <div class="stat-label">Active Sessions</div>
        <div class="stat-bar"><div class="stat-bar-fill stat-bar-green" style="width:100%"></div></div>
      </div>
      <div class="stat-card stat-blue">
        <div class="stat-value">{{ taskCount || '—' }}</div>
        <div class="stat-label">Total Tasks</div>
        <div class="stat-bar"><div class="stat-bar-fill stat-bar-blue" style="width:70%"></div></div>
      </div>
      <div class="stat-card stat-amber">
        <div class="stat-value">{{ listeners }}</div>
        <div class="stat-label">Listeners</div>
        <div class="stat-bar-group">
          <span class="stat-bar-seg stat-bar-amber"></span>
          <span class="stat-bar-seg stat-bar-amber dim"></span>
          <span class="stat-bar-seg stat-bar-amber dimmer"></span>
        </div>
      </div>
      <div class="stat-card stat-purple">
        <div class="stat-value">{{ onlineMinutes }}m</div>
        <div class="stat-label">Uptime</div>
        <div class="stat-bar"><div class="stat-bar-fill stat-bar-purple" :style="{ width: Math.min(onlineMinutes / 60 * 100, 100) + '%' }"></div></div>
      </div>
    </div>

    <!-- Main content grid -->
    <div class="content-grid">
      <!-- OS Distribution -->
      <div class="panel">
        <div class="panel-header">
          <h2>OS DISTRIBUTION</h2>
          <span class="panel-subtitle">{{ sessions.length }} hosts</span>
        </div>
        <div class="panel-body">
          <div v-for="(count, os) in osStats" :key="os" class="os-row">
            <div class="os-label-row">
              <span class="os-name">{{ os || 'unknown' }}</span>
              <span class="os-count">{{ count }}</span>
            </div>
            <div class="os-bar-bg">
              <div class="os-bar-fill" :class="osBarColor(os)" :style="{ width: (count / sessions.length * 100) + '%' }"></div>
            </div>
          </div>
          <div v-if="Object.keys(osStats).length === 0" class="empty-state">
            No sessions connected
          </div>
        </div>
      </div>

      <!-- Recent Sessions -->
      <div class="panel">
        <div class="panel-header">
          <h2>RECENT SESSIONS</h2>
          <span class="panel-subtitle">{{ sessions.length }} active</span>
        </div>
        <div class="session-list">
          <div v-for="s in sessions.slice(0, 8)" :key="s.ID"
            class="session-item"
            @click="$router.push('/sessions')">
            <div class="session-top">
              <div class="session-name">
                <span class="session-dot" :class="s.State === 'active' ? 'dot-active' : 'dot-inactive'"></span>
                <span>{{ s.Hostname || 'unknown' }}</span>
              </div>
              <div class="session-meta">
                <span class="capitalize">{{ s.OS || '?' }}</span>
                <span>{{ s.Arch || '?' }}</span>
              </div>
            </div>
            <div class="session-bottom">
              <span>{{ s.Username || '?' }}</span>
              <span v-if="s.IsAdmin" class="admin-badge">ADMIN</span>
            </div>
          </div>
          <div v-if="sessions.length === 0" class="empty-state">
            <div class="empty-icon">◈</div>
            <p>Awaiting agent connections...</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Quick Command -->
    <div class="panel">
      <div class="panel-header">
        <h2>QUICK COMMAND</h2>
        <span class="panel-subtitle">broadcast or target</span>
      </div>
      <div class="panel-body">
        <div class="cmd-row">
          <select v-model="targetAgent" class="cmd-select">
            <option value="">ALL AGENTS (broadcast)</option>
            <option v-for="s in sessions" :key="s.ID" :value="s.ID">{{ s.Hostname }} ({{ s.Username }})</option>
          </select>
          <input v-model="quickCmd" @keyup.enter="runQuickCmd"
            class="cmd-input"
            placeholder="$ command..." />
          <button @click="runQuickCmd" class="cmd-btn" :disabled="executing">{{ executing ? 'Executing...' : 'EXECUTE' }}</button>
        </div>
        <pre v-if="cmdResult" class="cmd-output" :class="{'cmd-error': cmdError}">{{ cmdResult }}</pre>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      sessions: [], taskCount: null, listeners: 0, uptime: 0,
      onlineMinutes: 0, osStats: {}, quickCmd: '', targetAgent: '', cmdResult: '', cmdError: false, executing: false,
      timer: null
    }
  },
  mounted() {
    this.refresh()
    this.timer = setInterval(() => this.refresh(), 4000)
  },
  beforeUnmount() { clearInterval(this.timer) },
  methods: {
    auth() {
      const token = sessionStorage.getItem('bty_token')
      return token ? { Authorization: 'Bearer ' + token } : {}
    },
    async refresh() {
      try {
        const [sessRes, healthRes] = await Promise.all([
          fetch('/api/sessions', { headers: this.auth() }),
          fetch('/api/health', { headers: this.auth() })
        ])
        if (sessRes.status === 401 || healthRes.status === 401) {
          this.$router.push('/login')
          return
        }
        this.sessions = await sessRes.json() || []
        const h = await healthRes.json()
        this.listeners = h.listeners || 0
        this.uptime = h.uptime || 0
        this.onlineMinutes = Math.floor((Date.now()/1000 - this.uptime) / 60) || 0
        this.taskCount = h.total_tasks ?? h.task_count ?? null
        this.osStats = {}
        this.sessions.forEach(s => {
          const os = s.OS || 'unknown'
          this.osStats[os] = (this.osStats[os] || 0) + 1
        })
      } catch (e) {
        console.error('Dashboard refresh failed:', e)
      }
    },
    osBarColor(os) {
      const colors = { linux: 'bar-amber', windows: 'bar-blue', darwin: 'bar-gray' }
      return colors[os] || 'bar-green'
    },
    async runQuickCmd() {
      if (!this.quickCmd || this.executing) return
      this.executing = true
      this.cmdResult = ''
      this.cmdError = false
      const url = this.targetAgent ? '/api/cmd' : '/api/broadcast'
      const body = this.targetAgent
        ? JSON.stringify({ agent_id: this.targetAgent, command: this.quickCmd, timeout: 15 })
        : JSON.stringify({ command: this.quickCmd })
      try {
        const r = await fetch(url, {
          method: 'POST',
          headers: { ...this.auth(), 'Content-Type': 'application/json' },
          body
        })
        if (r.status === 401) {
          this.$router.push('/login')
          return
        }
        const j = await r.json()
        if (!r.ok) {
          this.cmdResult = 'Error: ' + (j.error || r.statusText)
          this.cmdError = true
        } else {
          this.cmdResult = typeof j === 'string' ? j : JSON.stringify(j, null, 2)
        }
      } catch (e) {
        this.cmdResult = 'Connection error: ' + e.message
        this.cmdError = true
      }
      this.quickCmd = ''
      this.executing = false
    }
  }
}
</script>

<style scoped>
.dashboard-page { animation: fadeIn 0.5s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

.dash-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.dash-title { font-size: 22px; font-weight: 700; color: #111827; font-family: 'JetBrains Mono', monospace; }
.dash-subtitle { font-size: 13px; color: #6b7280; margin-top: 4px; }
.live-indicator { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #10b981; font-family: 'JetBrains Mono', monospace; font-weight: 600; }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
.stat-card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; border-left: 3px solid; transition: all 0.3s ease; }
.stat-card:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
.stat-green { border-left-color: #10b981; }
.stat-blue { border-left-color: #3b82f6; }
.stat-amber { border-left-color: #f59e0b; }
.stat-purple { border-left-color: #8b5cf6; }
.stat-value { font-size: 28px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
.stat-green .stat-value { color: #10b981; }
.stat-blue .stat-value { color: #3b82f6; }
.stat-amber .stat-value { color: #f59e0b; }
.stat-purple .stat-value { color: #8b5cf6; }
.stat-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 8px; }
.stat-bar { margin-top: 12px; height: 4px; background: #f3f4f6; border-radius: 2px; overflow: hidden; }
.stat-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
.stat-bar-green { background: #10b981; }
.stat-bar-blue { background: #3b82f6; }
.stat-bar-amber { background: #f59e0b; }
.stat-bar-purple { background: #8b5cf6; }
.stat-bar-group { display: flex; gap: 4px; margin-top: 12px; }
.stat-bar-seg { flex: 1; height: 4px; border-radius: 2px; background: #f59e0b; }
.stat-bar-seg.dim { opacity: 0.5; }
.stat-bar-seg.dimmer { opacity: 0.25; }

.content-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }
.panel { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; }
.panel-header { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid #f3f4f6; }
.panel-header h2 { font-size: 11px; font-weight: 600; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.05em; font-family: 'JetBrains Mono', monospace; }
.panel-subtitle { font-size: 11px; color: #9ca3af; font-family: 'JetBrains Mono', monospace; }
.panel-body { padding: 16px; }

.os-row { margin-bottom: 16px; }
.os-label-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
.os-name { font-size: 13px; color: #374151; font-family: 'JetBrains Mono', monospace; }
.os-count { font-size: 11px; color: #9ca3af; font-family: 'JetBrains Mono', monospace; }
.os-bar-bg { width: 100%; height: 8px; background: #f3f4f6; border-radius: 4px; overflow: hidden; }
.os-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; }
.bar-amber { background: #f59e0b; }
.bar-blue { background: #3b82f6; }
.bar-gray { background: #9ca3af; }
.bar-green { background: #10b981; }

.session-list { max-height: 300px; overflow-y: auto; }
.session-item { padding: 12px 16px; border-bottom: 1px solid #f3f4f6; cursor: pointer; transition: background 0.15s; }
.session-item:hover { background: #f9fafb; }
.session-item:last-child { border-bottom: none; }
.session-top { display: flex; align-items: center; justify-content: space-between; }
.session-name { display: flex; align-items: center; gap: 10px; font-size: 13px; color: #1f2937; font-family: 'JetBrains Mono', monospace; }
.session-dot { width: 8px; height: 8px; border-radius: 50%; }
.dot-active { background: #10b981; box-shadow: 0 0 6px rgba(16,185,129,0.4); }
.dot-inactive { background: #d1d5db; }
.session-meta { display: flex; gap: 12px; font-size: 11px; color: #9ca3af; font-family: 'JetBrains Mono', monospace; }
.session-bottom { display: flex; align-items: center; gap: 8px; margin-top: 6px; margin-left: 18px; font-size: 11px; color: #9ca3af; }
.admin-badge { font-size: 9px; font-weight: 700; color: #dc2626; background: #fee2e2; padding: 1px 6px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.05em; }

.cmd-row { display: flex; gap: 10px; }
.cmd-select { font-size: 12px; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 14px; outline: none; font-family: 'JetBrains Mono', monospace; min-width: 220px; background: #fff; }
.cmd-input { flex: 1; font-size: 13px; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 14px; outline: none; font-family: 'JetBrains Mono', monospace; transition: border-color 0.2s; }
.cmd-input:focus { border-color: #10b981; }
.cmd-btn { padding: 10px 24px; background: #10b981; color: #fff; border: none; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; font-family: 'JetBrains Mono', monospace; transition: background 0.2s; }
.cmd-btn:hover { background: #059669; }
.cmd-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.cmd-output { margin-top: 16px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; font-size: 12px; font-family: 'JetBrains Mono', monospace; max-height: 256px; overflow-y: auto; white-space: pre-wrap; color: #1f2937; }
.cmd-output.cmd-error { background: #fef2f2; border-color: #fecaca; color: #dc2626; }

.empty-state { text-align: center; padding: 32px 0; color: #9ca3af; font-size: 13px; font-family: 'JetBrains Mono', monospace; }
.empty-icon { font-size: 32px; margin-bottom: 8px; color: #d1d5db; }
</style>
