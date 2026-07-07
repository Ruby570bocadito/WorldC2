<template>
  <div>
    <div class="page-header"><h1>Files</h1><span class="badge" v-if="files.length">{{ files.length }} files</span></div>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Filename</th><th>Session</th><th>Module</th><th>Size</th><th>Created</th></tr></thead>
        <tbody>
          <tr v-for="f in files" :key="f.ID" class="row">
            <td class="mono fw6">{{ f.Filename }}</td><td class="mono small">{{ f.SessionID }}</td>
            <td>{{ f.Module }}</td><td class="mono small">{{ fmtSize(f.Size) }}</td>
            <td class="small">{{ fmtDate(f.Created) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
export default {
  data() { return { files: [], timer: null } },
  mounted() { this.fetch(); this.timer = setInterval(() => this.fetch(), 10000) },
  beforeUnmount() { clearInterval(this.timer) },
  methods: {
    auth() { const t = sessionStorage.getItem('bty_token'); return t ? { Authorization: 'Bearer ' + t } : {} },
    async fetch() {
      try {
        const r = await fetch('/api/files', { headers: this.auth() })
        if (r.status === 401) { this.$router.push('/login'); return }
        this.files = await r.json() || []
      } catch (e) { console.error('Failed to fetch files:', e) }
    },
    fmtDate(d) { return d ? new Date(d).toLocaleString() : '—' },
    fmtSize(b) { if (!b) return '—'; return b > 1048576 ? (b/1048576).toFixed(1)+' MB' : b > 1024 ? (b/1024).toFixed(0)+' KB' : b+' B' }
  }
}
</script>

<style scoped>
.page-header{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.page-header h1{font-size:22px;font-weight:700;color:#111827}
.badge{font-size:12px;background:#ecfdf5;color:#059669;padding:3px 10px;border-radius:20px;font-weight:500;font-family:'JetBrains Mono',monospace}
.table-wrap{background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{text-align:left;padding:10px 14px;font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;background:#fafbfc;border-bottom:1px solid #e5e7eb}
.table td{padding:10px 14px;border-bottom:1px solid #f3f4f6;color:#374151}
.row:hover{background:#f9fafb}
.mono{font-family:'JetBrains Mono',monospace}
.fw6{font-weight:600}
.small{font-size:12px}
</style>
