<template>
  <div class="vault">
    <div class="page-head">
      <div>
        <h1 class="page-title">Credential Vault</h1>
        <p class="page-sub">Captured credentials · {{ creds.length }} stored</p>
      </div>
      <div class="head-actions">
        <div class="search-box">
          <IconSearch :size="15" />
          <input
            v-model="query"
            class="input search-input"
            type="search"
            placeholder="Search user, host, domain…"
            aria-label="Search credentials"
            @input="debouncedSearch"
          />
        </div>
        <button
          class="btn btn-ghost"
          type="button"
          :disabled="!creds.length"
          title="Export the current listing (search filter included) as CSV"
          aria-label="Export credentials as CSV"
          @click="exportCSV"
        >
          <IconDownload :size="15" />
          <span>Export CSV</span>
        </button>
        <button class="btn btn-primary" type="button" @click="formOpen = !formOpen">
          <IconPlus :size="15" />
          <span>{{ formOpen ? 'Close' : 'New credential' }}</span>
        </button>
      </div>
    </div>

    <div v-if="formOpen" class="panel add-panel">
      <div class="panel-head">
        <span class="panel-title">Add credential</span>
      </div>
      <form class="panel-body add-form" @submit.prevent="create">
        <div class="add-grid">
          <div>
            <label class="field-label" for="vc-user">Username</label>
            <input id="vc-user" v-model="form.username" class="input mono" type="text" maxlength="128" autocomplete="off" />
          </div>
          <div>
            <label class="field-label" for="vc-pass">Password</label>
            <input id="vc-pass" v-model="form.password" class="input mono" type="text" maxlength="512" autocomplete="off" />
          </div>
          <div>
            <label class="field-label" for="vc-domain">Domain</label>
            <input id="vc-domain" v-model="form.domain" class="input mono" type="text" maxlength="128" autocomplete="off" />
          </div>
          <div>
            <label class="field-label" for="vc-host">Host</label>
            <input id="vc-host" v-model="form.host" class="input mono" type="text" maxlength="255" autocomplete="off" />
          </div>
          <div>
            <label class="field-label" for="vc-service">Service</label>
            <input id="vc-service" v-model="form.service" class="input mono" type="text" maxlength="64" autocomplete="off" />
          </div>
          <div>
            <label class="field-label" for="vc-source">Source</label>
            <input id="vc-source" v-model="form.source" class="input mono" type="text" maxlength="128" autocomplete="off" />
          </div>
          <div class="span-2">
            <label class="field-label" for="vc-notes">Notes (optional)</label>
            <input id="vc-notes" v-model="form.notes" class="input" type="text" maxlength="2000" autocomplete="off" />
          </div>
        </div>
        <p class="small muted hint">At least one identifying field is required · limits mirror the API caps</p>
        <p v-if="clientError" class="small danger-text">{{ clientError }}</p>
        <div class="add-actions">
          <button class="btn btn-primary" type="submit" :disabled="creating">
            {{ creating ? 'Storing…' : 'Store credential' }}
          </button>
        </div>
      </form>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>User</th>
            <th>Password</th>
            <th>Domain</th>
            <th>Host</th>
            <th>Service</th>
            <th>Source</th>
            <th>Captured</th>
            <th style="width: 90px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in creds" :key="c.id">
            <td class="mono fw">{{ c.username || '—' }}</td>
            <td class="mono pass-cell">
              <span v-if="revealed[c.id]">{{ c.password || '—' }}</span>
              <span v-else>{{ c.password ? '•'.repeat(Math.min(c.password.length, 10)) : '—' }}</span>
              <button
                v-if="c.password"
                class="icon-btn"
                type="button"
                :aria-label="(revealed[c.id] ? 'Hide' : 'Reveal') + ' password'"
                :title="revealed[c.id] ? 'Hide password' : 'Reveal password'"
                @click="toggleReveal(c.id)"
              >
                <IconKey :size="13" />
              </button>
            </td>
            <td class="mono">{{ c.domain || '—' }}</td>
            <td class="mono">{{ c.host || '—' }}</td>
            <td class="mono">{{ c.service || '—' }}</td>
            <td class="mono small">{{ c.source || '—' }}</td>
            <td class="num">{{ fmtDate(c.captured) }}</td>
            <td>
              <button
                class="icon-btn danger"
                type="button"
                :title="'Delete credential ' + (c.username || c.id)"
                aria-label="Delete credential"
                @click="remove(c)"
              >
                <IconTrash :size="15" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !creds.length" class="empty-state">
        <IconKey :size="30" />
        <span class="empty-title">{{ query ? 'No credentials match' : 'Vault is empty' }}</span>
        <span class="empty-hint">{{ query ? 'Try a different search term' : 'Captured credentials land here — add one above to seed the vault' }}</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading vault…</span>
      </div>
    </div>

    <!-- delete confirmation (replaces window.confirm — styled, explainer,
         and impossible to confirm with an accidental Enter on the row) -->
    <ConfirmModal
      v-if="pendingDelete"
      :title="'Delete credential ' + (pendingDelete.username || pendingDelete.id) + '?'"
      message="The record is removed from the vault permanently. This cannot be undone."
      confirm-label="Delete credential"
      danger
      :busy="deleting"
      @confirm="doDelete"
      @cancel="pendingDelete = null"
    />
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate } from '../utils/format.js'
import { toCSV, downloadText } from '../utils/csv.js'
import ConfirmModal from '../components/ConfirmModal.vue'
import { IconPlus, IconTrash, IconSearch, IconKey, IconDownload } from '../components/icons.js'

export default {
  name: 'VaultView',
  components: { IconPlus, IconTrash, IconSearch, IconKey, IconDownload, ConfirmModal },
  data() {
    return {
      creds: [],
      query: '',
      form: { username: '', password: '', domain: '', host: '', service: '', source: '', notes: '' },
      formOpen: false,
      creating: false,
      loading: true,
      clientError: '',
      revealed: {},
      searchTimer: null,
      pendingDelete: null,
      deleting: false,
    }
  },
  mounted() {
    this.fetchCreds()
  },
  methods: {
    fmtDate,
    toggleReveal(id) {
      this.revealed[id] = !this.revealed[id]
    },
    debouncedSearch() {
      clearTimeout(this.searchTimer)
      this.searchTimer = setTimeout(() => this.fetchCreds(), 250)
    },
    async fetchCreds() {
      try {
        const q = this.query.trim()
        const path = q ? '/api/vault?q=' + encodeURIComponent(q) : '/api/vault'
        const data = await api.get(path)
        this.creds = Array.isArray(data) ? data : []
      } catch (e) {
        if (e.status === 403) {
          notify.error('Vault read permission required')
        } else if (!e.expired) {
          notify.error('Failed to load vault: ' + e.message)
        }
      } finally {
        this.loading = false
      }
    },
    validate() {
      const f = this.form
      const meaningful = ['username', 'password', 'domain', 'host', 'service', 'source']
        .some((k) => f[k].trim() !== '')
      if (!meaningful) return 'At least one of username, password, domain, host, service or source is required'
      return ''
    },
    async create() {
      this.clientError = this.validate()
      if (this.clientError || this.creating) return
      this.creating = true
      try {
        // POST /api/vault — the API caps every field (username 128, password
        // 512, domain 128, host 255, service 64, source 128, notes 2000);
        // the inputs carry matching maxlength attributes.
        await api.post('/api/vault', {
          username: this.form.username.trim(),
          password: this.form.password,
          domain: this.form.domain.trim(),
          host: this.form.host.trim(),
          service: this.form.service.trim(),
          source: this.form.source.trim(),
          notes: this.form.notes,
        })
        notify.ok('Credential stored')
        this.form = { username: '', password: '', domain: '', host: '', service: '', source: '', notes: '' }
        this.formOpen = false
        this.clientError = ''
        this.fetchCreds()
      } catch (e) {
        if (!e.expired) notify.error('Store failed: ' + e.message)
      } finally {
        this.creating = false
      }
    },
    // Two-step delete: stage the row, let ConfirmModal collect the final
    // decision, act only on its confirm event.
    remove(c) {
      this.pendingDelete = c
    },
    async doDelete() {
      const c = this.pendingDelete
      if (!c || this.deleting) return
      this.deleting = true
      try {
        // DELETE /api/vault?id=... — admin only (vault:delete).
        await api.del('/api/vault?id=' + encodeURIComponent(c.id))
        notify.ok('Credential deleted')
        delete this.revealed[c.id]
        this.pendingDelete = null
        this.fetchCreds()
      } catch (e) {
        if (e.status === 403) {
          notify.error('Admin access required to delete credentials')
        } else if (!e.expired) {
          notify.error('Delete failed: ' + e.message)
        }
      } finally {
        this.deleting = false
      }
    },
    exportCSV() {
      if (!this.creds.length) return
      // Exports exactly what the operator is looking at: the active search
      // filter stays applied. Passwords are included on purpose — this is a
      // credential hand-off artifact for the engagement report; the CSV
      // serializer formula-injection-guards every cell (csv.js).
      const csv = toCSV(
        ['username', 'password', 'domain', 'host', 'service', 'source', 'captured'],
        this.creds,
        ['username', 'password', 'domain', 'host', 'service', 'source', 'captured']
      )
      const stamp = new Date().toISOString().slice(0, 10)
      downloadText('worldc2-vault-' + stamp + '.csv', csv)
      notify.ok('Exported ' + this.creds.length + ' credential(s)')
    },
  },
}
</script>

<style scoped>
.vault { max-width: 1080px; }

.head-actions { display: flex; align-items: center; gap: 10px; }
.search-box {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--muted);
}
.search-input { width: 230px; }

.add-panel { margin-bottom: 16px; }
.add-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
}
.span-2 { grid-column: 1 / -1; }
.hint { margin-top: 10px; }
.add-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}

.fw { font-weight: 600; }
.pass-cell { display: flex; align-items: center; gap: 6px; }
.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}
</style>
