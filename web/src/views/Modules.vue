<template>
  <div>
    <div class="page-head">
      <div>
        <h1 class="page-title">Modules</h1>
        <p class="page-sub">Push capability modules to agents</p>
      </div>
      <span v-if="modules.length" class="badge">{{ modules.length }} available</span>
    </div>

    <div v-if="loading" class="loading-grid">
      <div v-for="i in 4" :key="i" class="skeleton module-skeleton" />
    </div>

    <div v-else-if="modules.length" class="modules-grid">
      <div v-for="m in modules" :key="m.name" class="module-card panel">
        <div class="module-head">
          <span class="module-name mono">{{ m.name }}</span>
          <span class="mono small faint">{{ m.version ? 'v' + m.version : '' }}</span>
        </div>
        <div class="module-platform small mono">{{ m.platform || 'all' }}</div>
        <p class="module-desc">{{ m.description || 'No description.' }}</p>

        <div v-if="m.commands && m.commands.length" class="module-commands">
          <span v-for="cmd in m.commands.slice(0, 4)" :key="cmd" class="cmd-tag mono">{{ cmd }}</span>
        </div>

        <div class="module-actions">
          <select v-model="targets[m.name]" class="select module-select" :aria-label="'Target for ' + m.name">
            <option value="" disabled>Select session…</option>
            <option v-for="s in activeSessions" :key="s.ID" :value="s.ID">
              {{ s.Hostname || shortId(s.ID) }}
            </option>
          </select>
          <button
            class="btn btn-primary btn-sm"
            type="button"
            :disabled="!targets[m.name] || busy[m.name]"
            @click="push(m)"
          >
            <span v-if="busy[m.name]" class="spinner" />
            <span>{{ busy[m.name] ? 'Pushing…' : 'Push' }}</span>
          </button>
          <button
            class="icon-btn danger"
            type="button"
            :title="'Delete module ' + m.name"
            aria-label="Delete module"
            @click="remove(m)"
          >
            <IconTrash :size="15" />
          </button>
        </div>

        <p
          v-if="results[m.name]"
          class="module-result small mono"
          :class="results[m.name].error ? 'danger-text' : 'ok-text'"
        >
          {{ results[m.name].text }}
        </p>
      </div>
    </div>

    <div v-else class="panel">
      <div class="empty-state">
        <IconModules :size="30" />
        <span class="empty-title">No modules registered</span>
        <span class="empty-hint">Module manifests appear here once the server loads them</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { shortId } from '../utils/format.js'
import { IconTrash, IconModules } from '../components/icons.js'

export default {
  name: 'ModulesView',
  components: { IconTrash, IconModules },
  data() {
    return {
      modules: [],
      sessions: [],
      targets: {},
      busy: {},
      results: {},
      loading: true,
      timer: null,
    }
  },
  computed: {
    activeSessions() {
      return this.sessions.filter((s) => s.State === 'active')
    },
  },
  mounted() {
    this.refresh()
    this.timer = setInterval(() => this.fetchSessions(), 5000)
  },
  beforeUnmount() {
    if (this.timer) clearInterval(this.timer)
  },
  methods: {
    shortId,
    async refresh() {
      await Promise.allSettled([this.fetchModules(), this.fetchSessions()])
      this.loading = false
    },
    async fetchModules() {
      try {
        const data = await api.get('/api/modules')
        this.modules = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to load modules: ' + e.message)
      }
    },
    async fetchSessions() {
      try {
        const data = await api.get('/api/sessions')
        this.sessions = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to load sessions: ' + e.message)
      }
    },
    setResult(name, text, error = false) {
      this.results = { ...this.results, [name]: { text, error } }
    },
    async push(m) {
      const agentId = this.targets[m.name]
      if (!agentId || this.busy[m.name]) return
      this.busy = { ...this.busy, [m.name]: true }
      this.setResult(m.name, '')
      try {
        // POST /api/modules/push { module, agent_id }
        const data = await api.post('/api/modules/push', { module: m.name, agent_id: agentId })
        if (data && data.status === 'pushed') {
          this.setResult(m.name, '✓ pushed · ' + (data.output ? String(data.output).slice(0, 120) : 'acknowledged by agent'))
          notify.ok('Module "' + m.name + '" pushed')
        } else {
          const msg = (data && data.error) || 'Push failed'
          this.setResult(m.name, '✗ ' + msg, true)
          notify.error('Push failed: ' + msg)
        }
      } catch (e) {
        if (!e.expired) {
          this.setResult(m.name, '✗ ' + e.message, true)
          notify.error('Push failed: ' + e.message)
        }
      } finally {
        this.busy = { ...this.busy, [m.name]: false }
      }
    },
    async remove(m) {
      const ok = window.confirm('Delete module "' + m.name + '" from the store?')
      if (!ok) return
      try {
        // DELETE /api/modules/:name
        await api.del('/api/modules/' + encodeURIComponent(m.name))
        notify.ok('Module "' + m.name + '" deleted')
        this.fetchModules()
      } catch (e) {
        if (!e.expired) notify.error('Delete failed: ' + e.message)
      }
    },
  },
}
</script>

<style scoped>
.loading-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}
.module-skeleton { height: 190px; }

.modules-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}
.module-card {
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.module-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
}
.module-name { font-size: 15px; font-weight: 700; }
.module-platform { color: var(--accent); text-transform: uppercase; letter-spacing: 0.05em; }
.module-desc {
  font-size: 12.5px;
  color: var(--muted);
  line-height: 1.55;
  min-height: 38px;
}
.module-commands { display: flex; flex-wrap: wrap; gap: 5px; }
.cmd-tag {
  font-size: 10.5px;
  color: var(--muted);
  background: var(--surface-2);
  border: 1px solid var(--border-soft);
  padding: 2px 7px;
  border-radius: 5px;
}
.module-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: auto;
  padding-top: 6px;
}
.module-select { flex: 1; min-width: 0; }
.module-result { word-break: break-word; }
</style>
