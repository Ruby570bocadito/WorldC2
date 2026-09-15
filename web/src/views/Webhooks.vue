<template>
  <div class="webhooks">
    <div class="page-head">
      <div>
        <h1 class="page-title">Webhooks</h1>
        <p class="page-sub">SIEM forwarding destinations · admin only</p>
      </div>
      <button class="btn btn-primary" type="button" @click="formOpen = !formOpen">
        <IconPlus :size="15" />
        <span>{{ formOpen ? 'Close' : 'New webhook' }}</span>
      </button>
    </div>

    <div v-if="formOpen" class="panel add-panel">
      <div class="panel-head">
        <span class="panel-title">Create webhook</span>
      </div>
      <form class="panel-body add-form" @submit.prevent="create">
        <div class="add-grid">
          <div class="span-2">
            <label class="field-label" for="wh-url">Endpoint URL (https recommended)</label>
            <input
              id="wh-url"
              v-model="form.url"
              class="input mono"
              type="url"
              required
              maxlength="2048"
              autocomplete="off"
              placeholder="https://siem.corp.example/hook"
            />
          </div>
          <div>
            <label class="field-label" for="wh-timeout">Timeout (ms, 100–60000)</label>
            <input
              id="wh-timeout"
              v-model.number="form.timeout_ms"
              class="input mono"
              type="number"
              min="100"
              max="60000"
              step="100"
              required
            />
          </div>
        </div>
        <div class="headers-block">
          <span class="field-label">Custom headers (optional, up to 16)</span>
          <div v-for="(h, i) in form.headers" :key="i" class="header-row">
            <input
              v-model="h.name"
              class="input mono"
              type="text"
              maxlength="128"
              :placeholder="'Name ' + (i + 1) + ' (e.g. Authorization)'"
              :aria-label="'Header ' + (i + 1) + ' name'"
              autocomplete="off"
            />
            <input
              v-model="h.value"
              class="input mono"
              type="text"
              maxlength="1024"
              placeholder="Value (e.g. Bearer …)"
              :aria-label="'Header ' + (i + 1) + ' value'"
              autocomplete="off"
            />
            <button
              class="icon-btn danger"
              type="button"
              :aria-label="'Remove header ' + (i + 1)"
              title="Remove header"
              @click="form.headers.splice(i, 1)"
            >
              <IconTrash :size="14" />
            </button>
          </div>
          <button
            class="btn btn-ghost btn-sm"
            type="button"
            :disabled="form.headers.length >= 16"
            @click="form.headers.push({ name: '', value: '' })"
          >
            <IconPlus :size="13" />
            <span>Add header</span>
          </button>
        </div>
        <div class="events-block">
          <span class="field-label">Events (none selected = forward everything)</span>
          <div class="events-grid">
            <label v-for="ev in eventTypes" :key="ev" class="event-check">
              <input type="checkbox" :value="ev" v-model="form.events" />
              <span class="mono small">{{ ev }}</span>
            </label>
          </div>
        </div>
        <p v-if="clientError" class="small danger-text">{{ clientError }}</p>
        <div class="add-actions">
          <button class="btn btn-primary" type="submit" :disabled="creating">
            {{ creating ? 'Creating…' : 'Create webhook' }}
          </button>
        </div>
      </form>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Endpoint</th>
            <th>Events</th>
            <th>Deliveries</th>
            <th>Timeout</th>
            <th>Created</th>
            <th style="width: 90px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="wh in webhooks" :key="wh.id">
            <td class="mono fw url-cell">{{ wh.url }}</td>
            <td>
              <span v-if="!wh.events || !wh.events.length" class="small muted">all events</span>
              <span v-else class="events-cell">
                <span v-for="ev in wh.events" :key="ev" class="event-tag mono">{{ ev }}</span>
              </span>
            </td>
            <td>
              <span v-if="wh.stats && (wh.stats.delivered || wh.stats.failed)" class="stats-cell">
                <span class="stat-badge ok" :title="'Last: ' + (wh.stats.last_delivery || '—')">
                  {{ wh.stats.delivered }} ok
                </span>
                <span v-if="wh.stats.failed" class="stat-badge fail" :title="wh.stats.last_status || ''">
                  {{ wh.stats.failed }} failed
                </span>
                <span class="small muted">{{ fmtDate(wh.stats.last_delivery) }}</span>
              </span>
              <span v-else class="small muted">no attempts yet</span>
            </td>
            <td class="num">{{ wh.timeout_ms }}ms</td>
            <td class="num">{{ fmtDate(wh.created_at) }}</td>
            <td>
              <button
                class="icon-btn danger"
                type="button"
                :title="'Delete webhook ' + wh.url"
                aria-label="Delete webhook"
                @click="remove(wh)"
              >
                <IconTrash :size="15" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !webhooks.length" class="empty-state">
        <IconWebhook :size="30" />
        <span class="empty-title">No SIEM destinations</span>
        <span class="empty-hint">Events are forwarded as they happen — register a webhook above</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading webhooks…</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate } from '../utils/format.js'
import { IconPlus, IconTrash, IconWebhook } from '../components/icons.js'

// Must mirror the server-side allowlist (knownSIEMEvents in handlers.go).
const EVENT_TYPES = [
  'session_established',
  'session_disconnect',
  'session_passive',
  'session_error',
  'task_result',
  'agent_killed',
  'agent_purged',
  'operator_login',
]

export default {
  name: 'WebhooksView',
  components: { IconPlus, IconTrash, IconWebhook },
  data() {
    return {
      webhooks: [],
      eventTypes: EVENT_TYPES,
      form: { url: '', timeout_ms: 5000, events: [], headers: [] },
      formOpen: false,
      creating: false,
      loading: true,
      clientError: '',
    }
  },
  mounted() {
    this.fetchWebhooks()
  },
  methods: {
    fmtDate,
    validate() {
      const f = this.form
      let url
      try {
        url = new URL(f.url)
      } catch {
        return 'A valid absolute URL is required'
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'Only http(s) URLs are allowed'
      if (f.url.length > 2048) return 'URL must be 2048 characters or fewer'
      if (!Number.isInteger(f.timeout_ms) || f.timeout_ms < 100 || f.timeout_ms > 60000) {
        return 'Timeout must be between 100 and 60000 ms'
      }
      for (const ev of f.events) {
        if (!this.eventTypes.includes(ev)) return 'Unknown event type selected'
      }
      const seen = new Set()
      for (const h of f.headers) {
        const name = h.name.trim()
        if (!name) return 'Header names cannot be empty'
        if (name.length > 128) return 'Header names must be 128 characters or fewer'
        if (h.value.length > 1024) return 'Header values must be 1024 characters or fewer'
        const lower = name.toLowerCase()
        if (seen.has(lower)) return 'Duplicate header name: ' + name
        seen.add(lower)
      }
      return ''
    },
    async fetchWebhooks() {
      try {
        const data = await api.get('/api/webhooks')
        this.webhooks = Array.isArray(data) ? data : []
      } catch (e) {
        if (e.status === 403) {
          notify.error('Admin access required')
        } else if (!e.expired) {
          notify.error('Failed to load webhooks: ' + e.message)
        }
      } finally {
        this.loading = false
      }
    },
    async create() {
      this.clientError = this.validate()
      if (this.clientError || this.creating) return
      this.creating = true
      try {
        // POST /api/webhooks { url, headers, timeout_ms, events }
        const headers = {}
        for (const h of this.form.headers) {
          if (h.name.trim()) headers[h.name.trim()] = h.value
        }
        await api.post('/api/webhooks', {
          url: this.form.url,
          headers: Object.keys(headers).length ? headers : undefined,
          timeout_ms: this.form.timeout_ms,
          events: this.form.events,
        })
        notify.ok('Webhook registered')
        this.form = { url: '', timeout_ms: 5000, events: [], headers: [] }
        this.formOpen = false
        this.clientError = ''
        this.fetchWebhooks()
      } catch (e) {
        if (!e.expired) notify.error('Create failed: ' + e.message)
      } finally {
        this.creating = false
      }
    },
    async remove(wh) {
      const ok = window.confirm('Delete webhook "' + wh.url + '"?')
      if (!ok) return
      try {
        // DELETE /api/webhooks?id=...
        await api.del('/api/webhooks?id=' + encodeURIComponent(wh.id))
        notify.ok('Webhook deleted')
        this.fetchWebhooks()
      } catch (e) {
        if (!e.expired) notify.error('Delete failed: ' + e.message)
      }
    },
  },
}
</script>

<style scoped>
.webhooks { max-width: 960px; }

.add-panel { margin-bottom: 16px; }
.add-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
}
.span-2 { grid-column: 1 / -1; }
.add-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
.events-block { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
.events-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
  gap: 6px;
}
.event-check {
  display: flex;
  align-items: center;
  gap: 7px;
  cursor: pointer;
  color: var(--muted);
}
.event-check:hover { color: var(--text); }

.headers-block { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
.header-row {
  display: grid;
  grid-template-columns: minmax(140px, 1fr) minmax(200px, 2fr) auto;
  gap: 8px;
  align-items: center;
}

.stats-cell { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.stat-badge {
  font-size: 10.5px;
  padding: 2px 7px;
  border-radius: 5px;
  font-weight: 600;
}
.stat-badge.ok { color: var(--ok, #3fb68b); background: rgba(63, 182, 139, 0.12); }
.stat-badge.fail { color: var(--danger, #e5484d); background: rgba(229, 72, 77, 0.12); }

.url-cell { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.events-cell { display: flex; flex-wrap: wrap; gap: 4px; }
.event-tag {
  font-size: 10.5px;
  color: var(--muted);
  background: var(--surface-2);
  border: 1px solid var(--border-soft);
  padding: 2px 7px;
  border-radius: 5px;
}
.fw { font-weight: 600; }
.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}
</style>
