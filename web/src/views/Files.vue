<template>
  <div>
    <div class="page-head">
      <div>
        <h1 class="page-title">Files</h1>
        <p class="page-sub">Exfiltrated artifacts</p>
      </div>
      <span v-if="files.length" class="badge">{{ files.length }} files</span>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
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
      timer: null,
    }
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
  },
}
</script>

<style scoped>
.fw { font-weight: 600; }
.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}
</style>
