<template>
  <div class="audit">
    <div class="page-head">
      <div>
        <h1 class="page-title">Audit log</h1>
        <p class="page-sub">Append-only trail of every API call, auth event and lifecycle action · admin &amp; auditor</p>
      </div>
      <div class="head-side">
        <span v-if="entries.length" class="badge">{{ filtered.length }}/{{ entries.length }} events</span>
        <span class="badge" :class="hasError ? 'badge-danger' : 'badge-ok'">
          <span class="dot" :class="hasError ? 'dot-danger' : 'dot-ok'" />
          {{ hasError ? 'sync error' : 'live' }}
        </span>
      </div>
    </div>

    <!-- filters -->
    <div class="filters">
      <div class="search-box grow">
        <IconSearch :size="15" />
        <input
          v-model="query"
          class="input"
          type="search"
          placeholder="Filter by detail text or action…"
          aria-label="Filter audit entries"
        />
      </div>
      <select v-model="actionFilter" class="select filter-select" aria-label="Action filter">
        <option value="all">All actions</option>
        <option v-for="a in actions" :key="a" :value="a">{{ a }}</option>
      </select>
      <select v-model="limitFilter" class="select filter-select" aria-label="Page size" title="How many recent events to load (server caps at 500)">
        <option value="100">Last 100</option>
        <option value="250">Last 250</option>
        <option value="500">Last 500</option>
      </select>
      <button class="btn btn-ghost btn-sm" type="button" :disabled="loading" @click="fetchEntries">
        <IconRefresh :size="14" />
        <span>Refresh</span>
      </button>
    </div>

    <!-- table -->
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width: 160px">Time</th>
            <th style="width: 130px">Action</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in filtered" :key="e.id">
            <td class="num mono small">{{ fmtDate(e.created) }}</td>
            <td>
              <span class="action-pill mono" :class="actionClass(e.action)">{{ e.action }}</span>
            </td>
            <td class="detail-cell small">{{ e.detail || '—' }}</td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !entries.length" class="empty-state">
        <IconAudit :size="30" />
        <span class="empty-title">No audit events</span>
        <span class="empty-hint">Every API call lands here the moment it happens</span>
      </div>
      <div v-if="!loading && entries.length && !filtered.length" class="empty-state">
        <IconSearch :size="26" />
        <span class="empty-title">No events match the filter</span>
        <span class="empty-hint">Adjust the action filter or clear the search</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading audit trail…</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate } from '../utils/format.js'
import { IconSearch, IconRefresh, IconAudit } from '../components/icons.js'

export default {
  name: 'AuditView',
  components: { IconSearch, IconRefresh, IconAudit },
  data() {
    return {
      entries: [],
      loading: true,
      hasError: false,
      query: '',
      actionFilter: 'all',
      // Server contract: 1..500. The select only offers the sane sizes.
      limitFilter: '500',
      timer: null,
    }
  },
  computed: {
    actions() {
      return [...new Set(this.entries.map((e) => e.action).filter(Boolean))].sort()
    },
    filtered() {
      const q = this.query.trim().toLowerCase()
      return this.entries.filter((e) => {
        if (this.actionFilter !== 'all' && e.action !== this.actionFilter) return false
        if (!q) return true
        const hay = (e.action || '') + ' ' + (e.detail || '')
        return hay.toLowerCase().includes(q)
      })
    },
  },
  mounted() {
    this.fetchEntries()
    // 10s here: the trail is for human review, not the 5s operations poll —
    // a slower cadence keeps the audit endpoint out of the hot path.
    this.timer = setInterval(() => this.fetchEntries(), 10000)
  },
  beforeUnmount() {
    if (this.timer) clearInterval(this.timer)
  },
  methods: {
    fmtDate,
    actionClass(action) {
      if (action === 'auth_failed' || action === 'auth_denied') return 'is-danger'
      if (action === 'auth_success' || action === 'session_killed') return 'is-warn'
      return 'is-neutral'
    },
    async fetchEntries() {
      // limit comes from the select; the API rejects anything outside
      // 1..500, so keep the select the single source of truth.
      const limit = parseInt(this.limitFilter, 10)
      const path = '/api/audit?limit=' + (limit > 0 && limit <= 500 ? limit : 500)
      try {
        const data = await api.get(path)
        this.entries = Array.isArray(data) ? data : []
        this.hasError = false
      } catch (e) {
        if (!e.expired) notify.error('Failed to load audit trail: ' + e.message)
        this.hasError = true
      } finally {
        this.loading = false
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
.filters {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
}
.filter-select { width: 150px; flex-shrink: 0; }

.action-pill {
  display: inline-block;
  font-size: 11.5px;
  padding: 2px 9px;
  border-radius: 999px;
  border: 1px solid var(--border-soft);
  background: var(--surface-2);
}
.action-pill.is-danger {
  color: var(--danger, #e5484d);
  border-color: rgba(229, 72, 77, 0.4);
}
.action-pill.is-warn {
  color: var(--warning, #e5b348);
  border-color: rgba(229, 179, 72, 0.4);
}
.detail-cell {
  color: var(--muted);
  word-break: break-word;
}

.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}

@media (max-width: 640px) {
  .filters { flex-direction: column; }
  .filter-select { width: 100%; }
}
</style>
