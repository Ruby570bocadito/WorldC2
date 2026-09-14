<template>
  <div>
    <div class="page-head">
      <div>
        <h1 class="page-title">Files</h1>
        <p class="page-sub">Exfiltrated artifacts</p>
      </div>
      <div class="head-actions">
        <span v-if="files.length" class="badge">{{ files.length }} files</span>
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
            <th>Filename</th>
            <th>Session</th>
            <th>Module</th>
            <th>Size</th>
            <th>Captured</th>
            <th style="width: 88px" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in files" :key="f.id">
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
import { IconDownload, IconFiles, IconTrash } from '../components/icons.js'

export default {
  name: 'FilesView',
  components: { IconDownload, IconFiles, IconTrash },
  data() {
    return {
      files: [],
      loading: true,
      downloading: null,
      deleting: null,
      purgingAll: false,
      purgingSelected: false,
      selected: [],
      timer: null,
    }
  },
  computed: {
    selectedCount() {
      return this.selected.length
    },
    allSelected() {
      return this.files.length > 0 && this.selected.length === this.files.length
    },
  },
  mounted() {
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
        const data = await api.get('/api/files')
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
    toggleAll() {
      this.selected = this.allSelected ? [] : this.files.map((f) => f.id)
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
