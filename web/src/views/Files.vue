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
            <th style="width: 44px" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in files" :key="f.ID">
            <td class="mono fw">{{ f.Filename || '—' }}</td>
            <td class="num">{{ shortId(f.SessionID, 12) }}</td>
            <td class="muted">{{ f.Module || '—' }}</td>
            <td class="num">{{ fmtSize(f.Size) }}</td>
            <td class="num">{{ fmtDate(f.Created) }}</td>
            <td>
              <button
                class="icon-btn"
                type="button"
                :title="'Download ' + (f.Filename || 'file')"
                aria-label="Download file"
                :disabled="downloading === f.ID"
                @click="download(f)"
              >
                <span v-if="downloading === f.ID" class="spinner" />
                <IconDownload v-else :size="15" />
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
import { IconDownload, IconFiles } from '../components/icons.js'

export default {
  name: 'FilesView',
  components: { IconDownload, IconFiles },
  data() {
    return {
      files: [],
      loading: true,
      downloading: null,
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
      this.downloading = f.ID
      try {
        // GET /api/files/download/:id (Bearer auth via api layer)
        await downloadFile('/api/files/download/' + encodeURIComponent(f.ID), f.Filename)
      } catch (e) {
        if (!e.expired) notify.error('Download failed: ' + e.message)
      } finally {
        this.downloading = null
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
