<template>
  <div>
    <div class="page-head">
      <div>
        <h1 class="page-title">Files</h1>
        <p class="page-sub">Exfiltrated artifacts</p>
      </div>
      <div class="head-actions">
        <span v-if="files.length" class="badge">{{ filtered.length }}/{{ files.length }} files</span>
        <button
          v-if="selectedCount"
          class="btn btn-danger"
          type="button"
          :disabled="purgingSelected"
          @click="purgeSelected"
        >
          <span v-if="purgingSelected" class="spinner" />
          <IconTrash v-else :size="14" />
          Purge selected ({{ selectedCount }})
        </button>
        <button
          v-if="files.length"
          class="btn btn-danger"
          type="button"
          :disabled="purgingAll"
          @click="purgeAll"
        >
          <span v-if="purgingAll" class="spinner" />
          <IconTrash v-else :size="14" />
          Purge all
        </button>
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
          placeholder="Filter by filename, session or module…"
          aria-label="Filter files"
        />
      </div>
      <select v-model="sessionFilter" class="select filter-select" aria-label="Session filter">
        <option value="all">All sessions</option>
        <option v-for="s in sessions" :key="s" :value="s">{{ shortId(s, 12) }}</option>
      </select>
      <select v-model="daysFilter" class="select filter-select" aria-label="Time window" title="Show only files captured within this window">
        <option value="0">All time</option>
        <option value="1">Last 24h</option>
        <option value="7">Last 7 days</option>
        <option value="30">Last 30 days</option>
        <option value="90">Last 90 days</option>
      </select>
      <select v-model="moduleFilter" class="select filter-select" aria-label="Module filter">
        <option value="all">All modules</option>
        <option v-for="m in modules" :key="m" :value="m">{{ m }}</option>
      </select>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th class="col-check">
              <input
                type="checkbox"
                :checked="allSelected"
                aria-label="Select all files"
                @change="toggleAll"
              />
            </th>
            <th class="sortable" :aria-sort="ariaSort('filename')">
              <button type="button" class="th-btn" @click="setSort('filename')">
                Filename <span class="sort-ind" aria-hidden="true">{{ sortIndicator('filename') }}</span>
              </button>
            </th>
            <th>Session</th>
            <th>Module</th>
            <th class="sortable" :aria-sort="ariaSort('size')">
              <button type="button" class="th-btn" @click="setSort('size')">
                Size <span class="sort-ind" aria-hidden="true">{{ sortIndicator('size') }}</span>
              </button>
            </th>
            <th class="sortable" :aria-sort="ariaSort('created')">
              <button type="button" class="th-btn" @click="setSort('created')">
                Captured <span class="sort-ind" aria-hidden="true">{{ sortIndicator('created') }}</span>
              </button>
            </th>
            <th style="width: 88px" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in filtered" :key="f.id">
            <td class="col-check">
              <input
                type="checkbox"
                :checked="selected.includes(f.id)"
                :aria-label="'Select ' + (f.filename || f.id)"
                @change="toggle(f.id)"
              />
            </td>
            <td class="mono fw">{{ f.filename || '—' }}</td>
            <td class="num">{{ shortId(f.session_id, 12) }}</td>
            <td class="muted">{{ f.module || '—' }}</td>
            <td class="num">{{ fmtSize(f.size) }}</td>
            <td class="num">{{ fmtDate(f.created) }}</td>
            <td>
              <button
                class="icon-btn"
                type="button"
                :title="'Download ' + (f.filename || 'file')"
                aria-label="Download file"
                :disabled="downloading === f.id"
                @click="download(f)"
              >
                <span v-if="downloading === f.id" class="spinner" />
                <IconDownload v-else :size="15" />
              </button>
              <button
                class="icon-btn danger"
                type="button"
                :title="'Purge ' + (f.filename || 'file')"
                aria-label="Purge file"
                :disabled="deleting === f.id"
                @click="purge(f)"
              >
                <span v-if="deleting === f.id" class="spinner" />
                <IconTrash v-else :size="15" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !files.length" class="empty-state">
        <IconFiles :size="30" />
        <span class="empty-title">No files captured</span>
        <span class="empty-hint">Artifacts exfiltrated by modules will be listed here</span>
      </div>
      <div v-if="!loading && files.length && !filtered.length" class="empty-state">
        <IconSearch :size="26" />
        <span class="empty-title">No files match the filters</span>
        <span class="empty-hint">Adjust the session/module filters or clear the search</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading files…</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api, downloadFile } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate, fmtSize, shortId } from '../utils/format.js'
import { IconDownload, IconFiles, IconSearch, IconTrash } from '../components/icons.js'

export default {
  name: 'FilesView',
  components: { IconDownload, IconFiles, IconSearch, IconTrash },
  data() {
    return {
      files: [],
      loading: true,
      downloading: null,
      deleting: null,
      purgingAll: false,
      purgingSelected: false,
      selected: [],
      query: '',
      sessionFilter: 'all',
      moduleFilter: 'all',
      // 0 = all time; >0 maps to the ?days= API window.
      daysFilter: '0',
      sortKey: 'created',
      sortDir: -1,
      timer: null,
    }
  },
  computed: {
    selectedCount() {
      return this.selected.length
    },
    allSelected() {
      return this.filtered.length > 0 && this.filtered.every((f) => this.selected.includes(f.id))
    },
    sessions() {
      return [...new Set(this.files.map((f) => f.session_id).filter(Boolean))].sort()
    },
    modules() {
      return [...new Set(this.files.map((f) => f.module).filter(Boolean))].sort()
    },
    filtered() {
      const q = this.query.trim().toLowerCase()
      const rows = this.files.filter((f) => {
        if (this.sessionFilter !== 'all' && f.session_id !== this.sessionFilter) return false
        if (this.moduleFilter !== 'all' && f.module !== this.moduleFilter) return false
        if (!q) return true
        const hay = [f.filename, f.session_id, f.module].filter(Boolean).join(' ').toLowerCase()
        return hay.includes(q)
      })
      const dir = this.sortDir
      const key = this.sortKey
      return rows.sort((a, b) => {
        const av = a[key] || ''
        const bv = b[key] || ''
        if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir
        return String(av).localeCompare(String(bv)) * dir
      })
    },
  },
  watch: {
    // Deep-link support: Sessions pushes /files?session=<id> so the operator
    // lands on one session's loot directly.
    '$route.query.session'(v) {
      if (typeof v === 'string' && v) {
        this.sessionFilter = v
      }
    },
  },
  mounted() {
    const s = this.$route.query.session
    if (typeof s === 'string' && s) {
      this.sessionFilter = s
    }
    this.fetchFiles()
    this.timer = setInterval(() => this.fetchFiles(), 10000)
  },
  beforeUnmount() {
    if (this.timer) clearInterval(this.timer)
  },
  methods: {
    fmtDate,
    fmtSize,
    shortId,
    async fetchFiles() {
      try {
        // ?days=N is the server-side window (round 16); 0/absent keeps the
        // payload identical to the previous behavior.
        const days = parseInt(this.daysFilter, 10)
        const path = days > 0 ? '/api/files?days=' + days : '/api/files'
        const data = await api.get(path)
        this.files = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to load files: ' + e.message)
      } finally {
        this.loading = false
      }
    },
    async download(f) {
      if (this.downloading) return
      this.downloading = f.id
      try {
        // GET /api/files/download/:id (Bearer auth via api layer)
        await downloadFile('/api/files/download/' + encodeURIComponent(f.id), f.filename)
      } catch (e) {
        if (!e.expired) notify.error('Download failed: ' + e.message)
      } finally {
        this.downloading = null
      }
    },
    async purge(f) {
      const ok = window.confirm(
        'Purge "' + (f.filename || f.id) + '"? The artifact and its record are removed permanently.'
      )
      if (!ok) return
      this.deleting = f.id
      try {
        // DELETE /api/files/:id (Bearer auth via api layer)
        await api.del('/api/files/' + encodeURIComponent(f.id))
        notify.ok('File purged')
        this.fetchFiles()
      } catch (e) {
        if (!e.expired) notify.error('Purge failed: ' + e.message)
      } finally {
        this.deleting = null
      }
    },
    toggle(id) {
      const i = this.selected.indexOf(id)
      if (i >= 0) this.selected.splice(i, 1)
      else this.selected.push(id)
    },
    setSort(key) {
      if (this.sortKey === key) {
        this.sortDir = -this.sortDir
      } else {
        this.sortKey = key
        // Captured defaults to newest-first; the rest to ascending.
        this.sortDir = key === 'created' ? -1 : 1
      }
    },
    ariaSort(key) {
      if (this.sortKey !== key) return 'none'
      return this.sortDir === 1 ? 'ascending' : 'descending'
    },
    sortIndicator(key) {
      if (this.sortKey !== key) return ''
      return this.sortDir === 1 ? '↑' : '↓'
    },
    toggleAll() {
      const allMarked = this.filtered.every((f) => this.selected.includes(f.id))
      if (allMarked) {
        this.selected = this.selected.filter((id) => !this.filtered.some((f) => f.id === id))
      } else {
        const missing = this.filtered.map((f) => f.id).filter((id) => !this.selected.includes(id))
        this.selected = [...this.selected, ...missing]
      }
    },
    async purgeSelected() {
      const ids = [...this.selected]
      const ok = window.confirm(
        'Purge ' + ids.length + ' selected file(s)? Artifacts on disk and their records are removed permanently.'
      )
      if (!ok) return
      this.purgingSelected = true
      let purged = 0
      let failed = 0
      try {
        // DELETE /api/files/:id per selection. Sequential on purpose: a lab
        // scale list is small, and per-file results are clearer than a
        // single all-or-nothing call for a partial selection.
        for (const id of ids) {
          try {
            await api.del('/api/files/' + encodeURIComponent(id))
            purged++
          } catch (e) {
            if (e.expired) throw e
            failed++
          }
        }
        if (failed) {
          notify.error('Purged ' + purged + ', failed ' + failed)
        } else {
          notify.ok('Purged ' + purged + ' file(s)')
        }
        this.selected = []
        this.fetchFiles()
      } finally {
        this.purgingSelected = false
      }
    },
    async purgeAll() {
      const n = this.files.length
      const ok = window.confirm(
        'Purge ALL ' + n + ' file(s)? Artifacts on disk and their records are removed permanently.'
      )
      if (!ok) return
      this.purgingAll = true
      try {
        // DELETE /api/files (Bearer auth via api layer) — bulk wipe server-side
        const res = await api.del('/api/files')
        const count = res && typeof res.purged === 'number' ? res.purged : n
        notify.ok('Purged ' + count + ' file(s)')
        this.fetchFiles()
      } catch (e) {
        if (!e.expired) notify.error('Bulk purge failed: ' + e.message)
      } finally {
        this.purgingAll = null
      }
    },
  },
}
</script>

<style scoped>
.fw { font-weight: 600; }
.col-check {
  width: 34px;
  text-align: center;
}
.col-check input {
  accent-color: var(--accent, #6b8afd);
  cursor: pointer;
}
.sortable {
  cursor: pointer;
  user-select: none;
}
.sortable:hover {
  color: var(--text);
}
.th-btn {
  background: none;
  border: 0;
  padding: 0;
  font: inherit;
  color: inherit;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.th-btn:focus-visible {
  outline: 2px solid var(--accent, #6b8afd);
  outline-offset: 2px;
  border-radius: 3px;
}
.sort-ind {
  color: var(--faint);
  font-size: 10px;
}
.head-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}
</style>
