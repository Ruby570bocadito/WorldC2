<template>
  <div class="audit">
    <div class="page-head">
      <div>
        <h1 class="page-title">Audit log</h1>
        <p class="page-sub">Append-only trail of every API call, auth event and lifecycle action · admin &amp; auditor</p>
      </div>
      <div class="head-side">
        <span v-if="entries.length" class="badge">{{ filtered.length }}/{{ entries.length }} events</span>
        <button
          v-if="entries.length"
          class="btn btn-ghost btn-sm"
          type="button"
          title="Download the loaded trail as CSV (RFC 4180, formula-safe)"
          @click="exportCsv"
        >
          <IconDownload :size="14" />
          <span>Export CSV</span>
        </button>
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
      <select
        v-model="userFilter"
        class="select filter-select"
        aria-label="Operator filter"
        title="Server-side filter: only events attributed to this account"
        @change="fetchEntries"
      >
        <option value="">All operators</option>
        <option v-for="u in operators" :key="u" :value="u">{{ u }}</option>
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
            <th style="width: 120px">Operator</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in filtered" :key="e.id">
            <td class="num mono small">{{ fmtDate(e.created) }}</td>
            <td>
              <span class="action-pill mono" :class="actionClass(e.action)">{{ e.action }}</span>
            </td>
            <td class="small">
              <span v-if="e.operator" class="op-pill mono">{{ e.operator }}</span>
              <span v-else class="muted small">system</span>
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

      <!-- Cursor pagination (r19): appends the next OLDER page via
           before_id. Hides itself once a page comes back short of the
           requested size — the honest end-of-trail signal. -->
      <div v-if="canLoadMore && !loading" class="load-more">
        <button class="btn btn-ghost btn-sm" type="button" :disabled="loadingMore" @click="loadMore">
          {{ loadingMore ? 'Loading…' : 'Load more' }}
        </button>
        <span class="small faint">showing {{ entries.length }} events</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate } from '../utils/format.js'
import { toCSV, downloadText } from '../utils/csv.js'
import { IconSearch, IconRefresh, IconAudit, IconDownload } from '../components/icons.js'

export default {
  name: 'AuditView',
  components: { IconSearch, IconRefresh, IconAudit, IconDownload },
  data() {
    return {
      entries: [],
      loading: true,
      hasError: false,
      query: '',
      actionFilter: 'all',
      // Operator filter is SERVER-side (?user=): it walks the whole trail
      // of one account, not just the loaded page — attribution is the
      // point of the column.
      userFilter: '',
      // Server contract: 1..500. The select only offers the sane sizes.
      limitFilter: '500',
      timer: null,
      // Cursor pagination (r19): whether an older page may exist. A full
      // page means "maybe", a short page means "definitely not".
      canLoadMore: false,
      loadingMore: false,
    }
  },
  computed: {
    actions() {
      return [...new Set(this.entries.map((e) => e.action).filter(Boolean))].sort()
    },
    // Account select built from what the loaded page actually carries —
    // the audit API deliberately has no "list of all usernames" shape;
    // this keeps the select honest without widening the endpoint.
    operators() {
      return [...new Set(this.entries.map((e) => e.operator).filter(Boolean))].sort()
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
      // 1..500, so keep the select the single source of truth. The user
      // filter rides along server-side (?user=) when set. A refresh
      // resets the walk back to the first page.
      const limit = parseInt(this.limitFilter, 10)
      const size = limit > 0 && limit <= 500 ? limit : 500
      let path = '/api/audit?limit=' + size
      if (this.userFilter) path += '&user=' + encodeURIComponent(this.userFilter)
      try {
        const data = await api.get(path)
        this.entries = Array.isArray(data) ? data : []
        this.hasError = false
        this.canLoadMore = this.entries.length >= size
      } catch (e) {
        if (!e.expired) notify.error('Failed to load audit trail: ' + e.message)
        this.hasError = true
      } finally {
        this.loading = false
      }
    },
    async loadMore() {
      if (this.loadingMore || !this.entries.length) return
      this.loadingMore = true
      const limit = parseInt(this.limitFilter, 10)
      const size = limit > 0 && limit <= 500 ? limit : 500
      // The cursor is the OLDEST id currently loaded — audit ids are
      // monotonic, so "id < cursor" is exactly "everything older".
      const cursor = this.entries[this.entries.length - 1].id
      let path = '/api/audit?limit=' + size + '&before_id=' + encodeURIComponent(cursor)
      if (this.userFilter) path += '&user=' + encodeURIComponent(this.userFilter)
      try {
        const data = await api.get(path)
        const page = Array.isArray(data) ? data : []
        this.entries = this.entries.concat(page)
        this.canLoadMore = page.length >= size
      } catch (e) {
        if (!e.expired) notify.error('Failed to load more events: ' + e.message)
      } finally {
        this.loadingMore = false
      }
    },
    exportCsv() {
      // Same contract as Files/Vault: serialize what the CURRENT view
      // holds (filters applied), through the shared formula-guarded
      // serializer — audit details carry operator names and IPs and must
      // land as inert text in a spreadsheet.
      const rows = this.filtered.map((e) => ({
        id: e.id,
        created: new Date(e.created).toISOString(),
        action: e.action,
        operator: e.operator || 'system',
        detail: e.detail || '',
      }))
      const csv = toCSV(
        ['id', 'created', 'action', 'operator', 'detail'],
        rows,
        ['id', 'created', 'action', 'operator', 'detail']
      )
      const stamp = new Date().toISOString().slice(0, 10)
      downloadText('worldc2-audit-' + stamp + '.csv', csv)
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
.op-pill {
  display: inline-block;
  font-size: 11.5px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid rgba(110, 123, 242, 0.35);
  background: var(--accent-soft);
  color: var(--accent);
  max-width: 110px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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

.load-more {
  display: flex;
  align-items: center;
  gap: 12px;
  justify-content: center;
  padding: 14px;
  border-top: 1px solid var(--border-soft);
}

@media (max-width: 640px) {
  .filters { flex-direction: column; }
  .filter-select { width: 100%; }
}
</style>
