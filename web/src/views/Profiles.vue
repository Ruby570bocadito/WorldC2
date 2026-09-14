<template>
  <div class="profiles">
    <div class="page-head">
      <div>
        <h1 class="page-title">Profiles</h1>
        <p class="page-sub">Agent configuration profiles · beacon cadence and transport defaults</p>
      </div>
      <button class="btn btn-primary" type="button" @click="formOpen = !formOpen">
        <IconPlus :size="15" />
        <span>{{ formOpen ? 'Close' : 'New profile' }}</span>
      </button>
    </div>

    <div v-if="formOpen" class="panel add-panel">
      <div class="panel-head">
        <span class="panel-title">Create profile</span>
      </div>
      <form class="panel-body add-form" @submit.prevent="create">
        <div class="add-grid">
          <div>
            <label class="field-label" for="prof-name">Name</label>
            <input
              id="prof-name"
              v-model="form.name"
              class="input mono"
              type="text"
              required
              maxlength="64"
              autocomplete="off"
              placeholder="corp-beacon"
            />
          </div>
          <div>
            <label class="field-label" for="prof-interval">Beacon interval (s)</label>
            <input
              id="prof-interval"
              v-model.number="form.beacon_interval"
              class="input mono"
              type="number"
              min="1"
              max="3600"
              step="1"
              required
            />
          </div>
          <div>
            <label class="field-label" for="prof-jitter">Jitter (0–0.95)</label>
            <input
              id="prof-jitter"
              v-model.number="form.jitter"
              class="input mono"
              type="number"
              min="0"
              max="0.95"
              step="0.05"
              required
            />
          </div>
          <div>
            <label class="field-label" for="prof-transport">Transport</label>
            <select id="prof-transport" v-model="form.transport" class="select">
              <option v-for="t in transports" :key="t" :value="t">{{ t }}</option>
            </select>
          </div>
        </div>
        <p v-if="clientError" class="small danger-text">{{ clientError }}</p>
        <div class="add-actions">
          <button class="btn btn-primary" type="submit" :disabled="creating">
            {{ creating ? 'Creating…' : 'Create profile' }}
          </button>
        </div>
      </form>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Beacon</th>
            <th>Jitter</th>
            <th>Transport</th>
            <th>Created</th>
            <th style="width: 90px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="pr in profiles" :key="pr.id">
            <td class="mono fw">{{ pr.name }}</td>
            <td class="num">{{ pr.beacon_interval }}s</td>
            <td class="num">{{ fmtJitter(pr.jitter) }}</td>
            <td>
              <span class="badge badge-accent">{{ pr.transport }}</span>
            </td>
            <td class="num">{{ fmtDate(pr.created_at) }}</td>
            <td>
              <button
                class="icon-btn danger"
                type="button"
                :title="'Delete profile ' + pr.name"
                aria-label="Delete profile"
                @click="remove(pr)"
              >
                <IconTrash :size="15" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !profiles.length" class="empty-state">
        <IconProfiles :size="30" />
        <span class="empty-title">No profiles defined</span>
        <span class="empty-hint">Profiles set the default beacon cadence and transport for new agents</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading profiles…</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate } from '../utils/format.js'
import { IconPlus, IconTrash, IconProfiles } from '../components/icons.js'

// Must mirror the server-side allowlist in POST /api/profiles validation.
const TRANSPORTS = ['tls', 'http', 'dns', 'webrtc', 'ws', 'tcp']

export default {
  name: 'ProfilesView',
  components: { IconPlus, IconTrash, IconProfiles },
  data() {
    return {
      profiles: [],
      transports: TRANSPORTS,
      form: { name: '', beacon_interval: 5, jitter: 0.3, transport: 'tls' },
      formOpen: false,
      creating: false,
      loading: true,
      clientError: '',
    }
  },
  mounted() {
    this.fetchProfiles()
  },
  methods: {
    fmtDate,
    fmtJitter(j) {
      const n = Number(j)
      return Number.isFinite(n) ? Math.round(n * 100) + '%' : '—'
    },
    validate() {
      const f = this.form
      const name = f.name.trim()
      if (!name) return 'Name is required'
      if (name.length > 64) return 'Name must be 64 characters or fewer'
      if (!Number.isInteger(f.beacon_interval) || f.beacon_interval < 1 || f.beacon_interval > 3600) {
        return 'Beacon interval must be an integer between 1 and 3600 seconds'
      }
      if (!Number.isFinite(f.jitter) || f.jitter < 0 || f.jitter > 0.95) {
        return 'Jitter must be between 0 and 0.95'
      }
      if (!this.transports.includes(f.transport)) return 'Unknown transport'
      return ''
    },
    async fetchProfiles() {
      try {
        const data = await api.get('/api/profiles')
        this.profiles = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to load profiles: ' + e.message)
      } finally {
        this.loading = false
      }
    },
    async create() {
      this.clientError = this.validate()
      if (this.clientError || this.creating) return
      this.creating = true
      try {
        // POST /api/profiles { name, beacon_interval, jitter, transport }
        const data = await api.post('/api/profiles', {
          name: this.form.name.trim(),
          beacon_interval: this.form.beacon_interval,
          jitter: this.form.jitter,
          transport: this.form.transport,
        })
        notify.ok('Profile "' + this.form.name.trim() + '" created')
        this.form = { name: '', beacon_interval: 5, jitter: 0.3, transport: 'tls' }
        this.formOpen = false
        this.clientError = ''
        this.fetchProfiles()
        return data
      } catch (e) {
        if (!e.expired) notify.error('Create failed: ' + e.message)
      } finally {
        this.creating = false
      }
    },
    async remove(pr) {
      const ok = window.confirm('Delete profile "' + pr.name + '"?')
      if (!ok) return
      try {
        // DELETE /api/profiles/:id
        await api.del('/api/profiles/' + encodeURIComponent(pr.id))
        notify.ok('Profile "' + pr.name + '" deleted')
        this.fetchProfiles()
      } catch (e) {
        if (!e.expired) notify.error('Delete failed: ' + e.message)
      }
    },
  },
}
</script>

<style scoped>
.profiles { max-width: 900px; }

.add-panel { margin-bottom: 16px; }
.add-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px;
}
.add-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}

.fw { font-weight: 600; }
.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}
</style>
