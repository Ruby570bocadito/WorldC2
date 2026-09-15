<template>
  <div class="sessions">
    <div class="page-head">
      <div>
        <h1 class="page-title">Sessions</h1>
        <p class="page-sub">Connected agents and their state</p>
      </div>
      <span class="badge" :class="activeCount ? 'badge-ok' : ''">
        <span class="dot" :class="activeCount ? 'dot-ok' : ''" />
        {{ activeCount }} active
      </span>
    </div>

    <!-- filters -->
    <div class="filters">
      <div class="search-box grow">
        <IconSearch :size="15" />
        <input
          v-model="query"
          class="input"
          type="search"
          placeholder="Filter by hostname, user, IP, transport or agent id…"
          aria-label="Filter sessions"
        />
      </div>
      <select v-model="stateFilter" class="select filter-select" aria-label="State filter">
        <option value="all">All states</option>
        <option value="active">Active</option>
        <option value="inactive">Inactive</option>
      </select>
      <select v-model="daysFilter" class="select filter-select days-select" aria-label="Time window" title="Show only sessions last seen within this window">
        <option value="0">All time</option>
        <option value="1">Last 24h</option>
        <option value="7">Last 7 days</option>
        <option value="30">Last 30 days</option>
        <option value="90">Last 90 days</option>
      </select>
      <select v-model="transportFilter" class="select filter-select" aria-label="Transport filter">
        <option value="all">All transports</option>
        <option v-for="t in transports" :key="t" :value="t">{{ t }}</option>
      </select>
      <select v-model="versionFilter" class="select filter-select" aria-label="Agent version filter">
        <option value="all">All versions</option>
        <option v-for="v in versions" :key="v" :value="v">{{ v }}</option>
      </select>
    </div>

    <!-- table -->
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width: 26px" />
            <th>Hostname</th>
            <th>User</th>
            <th>Platform</th>
            <th>Transport</th>
            <th>IP</th>
            <th>State</th>
            <th>Last seen</th>
            <th style="width: 122px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="s in filtered"
            :key="s.ID"
            class="clickable"
            :class="{ expanded: expanded === s.ID }"
            @click="toggleExpand(s.ID)"
          >
            <td class="expand-cell">
              <span class="chev" :class="{ open: expanded === s.ID }">›</span>
            </td>
            <td class="mono fw">{{ s.Hostname || shortId(s.ID) }}</td>
            <td>
              {{ s.Username || '?' }}
              <span v-if="s.IsAdmin" class="tag-admin">ADMIN</span>
            </td>
            <td class="num">{{ (s.OS || '?') + ' / ' + (s.Arch || '?') }}</td>
            <td class="num">
              <span v-if="s.Transport || s.AgentVersion" class="transport mono">{{ s.Transport || '?' }}<span v-if="s.AgentVersion" class="faint"> · v{{ s.AgentVersion }}</span></span>
              <span v-else class="faint">—</span>
            </td>
            <td class="num">{{ ipOf(s) }}</td>
            <td>
              <span class="status-pill" :class="s.State === 'active' ? 'is-active' : 'is-down'">
                <span class="dot" :class="s.State === 'active' ? 'dot-ok' : ''" />
                {{ s.State || 'unknown' }}
              </span>
            </td>
            <td class="num">{{ fmtAgo(s.LastSeen) }}</td>
            <td class="actions-cell" @click.stop>
              <button
                class="icon-btn"
                type="button"
                title="View loot from this session"
                aria-label="View loot"
                @click="viewLoot(s)"
              >
                <IconFiles :size="15" />
              </button>
              <button
                class="icon-btn"
                type="button"
                title="Session notes"
                aria-label="Session notes"
                @click="openNotes(s)"
              >
                <IconNote :size="15" />
              </button>
              <button
                class="icon-btn danger"
                type="button"
                title="Kill session"
                aria-label="Kill session"
                @click="kill(s)"
              >
                <IconClose :size="15" />
              </button>
              <button
                class="icon-btn danger"
                type="button"
                title="Purge session (hard delete)"
                aria-label="Purge session"
                @click="purge(s)"
              >
                <IconTrash :size="15" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !filtered.length" class="empty-state">
        <IconSessions :size="30" />
        <span class="empty-title">{{ sessions.length ? 'No sessions match the filter' : 'No sessions yet' }}</span>
        <span class="empty-hint">Waiting for agents to check in…</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading sessions…</span>
      </div>
    </div>

    <!-- expanded detail -->
    <div v-if="expandedSession" class="detail panel">
      <div class="panel-head">
        <span class="panel-title mono">{{ expandedSession.Hostname || expandedSession.ID }}</span>
        <button class="icon-btn" type="button" aria-label="Close details" @click="expanded = null">
          <IconClose :size="15" />
        </button>
      </div>
      <div class="panel-body">
        <div class="detail-grid">
          <div class="detail-item"><label>Session ID</label><code>{{ expandedSession.ID }}</code></div>
          <div class="detail-item"><label>Agent ID</label><code>{{ expandedSession.AgentID || '—' }}</code></div>
          <div class="detail-item">
            <label>State</label>
            <span class="status-pill" :class="expandedSession.State === 'active' ? 'is-active' : 'is-down'">
              <span class="dot" :class="expandedSession.State === 'active' ? 'dot-ok' : ''" />
              {{ expandedSession.State || 'unknown' }}
            </span>
          </div>
          <div class="detail-item"><label>User</label><span>{{ expandedSession.Username || '?' }}<span v-if="expandedSession.IsAdmin" class="tag-admin">ADMIN</span></span></div>
          <div class="detail-item"><label>Platform</label><span>{{ (expandedSession.OS || '?') + ' ' + (expandedSession.Arch || '') }}</span></div>
          <div class="detail-item"><label>Transport / Agent version</label><span class="mono">{{ expandedSession.Transport || '—' }}<span v-if="expandedSession.AgentVersion"> · v{{ expandedSession.AgentVersion }}</span></span></div>
          <div class="detail-item"><label>Privilege</label><span>{{ expandedSession.Privilege || '—' }}<span v-if="expandedSession.IsAdmin" class="tag-admin">ADMIN</span></span></div>
          <div class="detail-item"><label>TLS fingerprint</label><span class="mono small">{{ expandedSession.Fingerprint || 'no mTLS pin' }}</span></div>
          <div class="detail-item"><label>IPs</label><span class="mono small">{{ expandedSession.PublicIP || '—' }} / {{ expandedSession.LocalIP || '—' }}</span></div>
          <div class="detail-item"><label>First seen</label><span>{{ fmtDate(expandedSession.FirstSeen) }}</span></div>
          <div class="detail-item"><label>Last seen</label><span>{{ fmtDate(expandedSession.LastSeen) }}</span></div>
          <div class="detail-item"><label>Tasks</label><span class="mono">{{ expandedSession.TaskCount || 0 }}</span></div>
        </div>

        <!-- task history -->
        <h3 class="section-title">
          Task history
          <span v-if="tasks.length" class="muted small">· showing {{ tasks.length }}</span>
        </h3>
        <div v-if="tasks.length" class="task-list">
          <div v-for="t in tasks" :key="t.ID" class="task-row">
            <div class="task-cmd mono">$ {{ t.Command }}</div>
            <pre v-if="t.Output" class="task-output mono">{{ t.Output }}</pre>
            <div v-else class="task-pending small faint">
              pending…
            </div>
          </div>
        </div>
        <div v-if="hasMoreTasks" class="load-more">
          <button class="btn btn-ghost btn-sm" type="button" :disabled="loadingMore" @click="loadMoreTasks">
            <span v-if="loadingMore" class="spinner" />
            <span>{{ loadingMore ? 'Loading…' : 'Load more' }}</span>
          </button>
          <span class="small faint">older tasks load on demand — the page never silently caps the history</span>
        </div>
        <p v-else-if="!tasks.length" class="faint small">No tasks recorded for this session.</p>
      </div>
    </div>

    <!-- notes dialog -->
    <div v-if="notesFor" class="modal-backdrop" @click.self="closeNotes">
      <div class="modal" role="dialog" aria-modal="true" aria-label="Session notes">
        <div class="panel-head">
          <span class="panel-title">Notes · {{ notesFor.Hostname || shortId(notesFor.ID) }}</span>
          <button class="icon-btn" type="button" aria-label="Close notes" @click="closeNotes">
            <IconClose :size="15" />
          </button>
        </div>
        <div class="panel-body modal-body">
          <div v-if="notes.length" class="notes-list">
            <div v-for="n in notes" :key="n.id" class="note-row">
              <p class="note-content">{{ n.content }}</p>
              <span class="small faint">{{ n.username || 'unknown' }} · {{ fmtDate(n.created_at) }}</span>
            </div>
          </div>
          <p v-else class="faint small">No notes for this session yet.</p>

          <form class="note-form" @submit.prevent="addNote">
            <textarea
              v-model="noteDraft"
              class="input"
              rows="3"
              placeholder="Write an operator note…"
              required
            />
            <button class="btn btn-primary" type="submit" :disabled="savingNote || !noteDraft.trim()">
              {{ savingNote ? 'Saving…' : 'Add note' }}
            </button>
          </form>
        </div>
      </div>
    </div>

    <!-- kill confirmation -->
    <ConfirmModal
      v-if="pendingKill"
      :title="'Kill session ' + (pendingKill.Hostname || shortId(pendingKill.ID)) + '?'"
      message="The agent will be terminated. The session row stays as a historical record with state 'killed'."
      confirm-label="Kill session"
      danger
      :busy="acting"
      @confirm="doKill"
      @cancel="pendingKill = null"
    />

    <!-- purge confirmation: the destructive variant, extra friction -->
    <ConfirmModal
      v-if="pendingPurge"
      :title="'Purge session ' + (pendingPurge.Hostname || shortId(pendingPurge.ID)) + '?'"
      message="The record, its tasks and its persisted loot are removed from the database permanently. This cannot be undone."
      confirm-label="Purge permanently"
      danger
      require-phrase="PURGE"
      :busy="acting"
      @confirm="doPurge"
      @cancel="pendingPurge = null"
    />
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtAgo, fmtDate, shortId, ipOf } from '../utils/format.js'
import ConfirmModal from '../components/ConfirmModal.vue'
import { IconSearch, IconNote, IconClose, IconSessions, IconTrash, IconFiles } from '../components/icons.js'

export default {
  name: 'SessionsView',
  components: { IconSearch, IconNote, IconClose, IconSessions, IconTrash, IconFiles, ConfirmModal },
  data() {
    return {
      sessions: [],
      loading: true,
      query: '',
      stateFilter: 'all',
      transportFilter: 'all',
      versionFilter: 'all',
      // 0 = all time; anything else maps to the ?days= API window.
      daysFilter: '0',
      // Two-step confirmations (ConfirmModal) — one at a time.
      pendingKill: null,
      pendingPurge: null,
      acting: false,
      expanded: null,
      tasks: [],
      // Task-history pagination (round 17): the server pages with an opaque
      // composite cursor; null cursor = "fetch the newest page".
      hasMoreTasks: false,
      taskCursor: null,
      loadingMore: false,
      // notes
      notesFor: null,
      notes: [],
      noteDraft: '',
      savingNote: false,
      timer: null,
    }
  },
  computed: {
    activeCount() {
      return this.sessions.filter((s) => s.State === 'active').length
    },
    transports() {
      return [...new Set(this.sessions.map((s) => s.Transport).filter(Boolean))].sort()
    },
    versions() {
      return [...new Set(this.sessions.map((s) => s.AgentVersion).filter(Boolean))].sort()
    },
    filtered() {
      const q = this.query.trim().toLowerCase()
      return this.sessions.filter((s) => {
        if (this.stateFilter === 'active' && s.State !== 'active') return false
        if (this.stateFilter === 'inactive' && s.State === 'active') return false
        if (this.transportFilter !== 'all' && s.Transport !== this.transportFilter) return false
        if (this.versionFilter !== 'all' && s.AgentVersion !== this.versionFilter) return false
        if (!q) return true
        const hay = [s.Hostname, s.Username, s.PublicIP, s.LocalIP, s.AgentID, s.ID, s.Transport, s.AgentVersion]
          .filter(Boolean)
          .join(' ')
          .toLowerCase()
        return hay.includes(q)
      })
    },
    expandedSession() {
      return this.sessions.find((s) => s.ID === this.expanded) || null
    },
  },
  mounted() {
    this.applyQueryFilters()
    this.fetchSessions()
    this.timer = setInterval(() => this.fetchSessions(), 5000)
  },
  watch: {
    // Deep-link support: the dashboard fleet chips push /sessions?transport=x
    // or /sessions?version=y. Watching the query keeps the filters in sync
    // even when the navigation lands on an already-mounted instance.
    '$route.query.transport'() {
      this.applyQueryFilters()
    },
    '$route.query.version'() {
      this.applyQueryFilters()
    },
  },
  beforeUnmount() {
    if (this.timer) clearInterval(this.timer)
  },
  methods: {
    fmtAgo,
    fmtDate,
    shortId,
    ipOf,
    viewLoot(s) {
      // Deep-link into Files with this session's loot pre-filtered
      // (Files reads ?session=).
      this.$router.push({ path: '/files', query: { session: s.ID } })
    },
    applyQueryFilters() {
      const t = this.$route.query.transport
      if (typeof t === 'string' && t) {
        this.transportFilter = t
      }
      const v = this.$route.query.version
      if (typeof v === 'string' && v) {
        this.versionFilter = v
      }
    },
    async fetchSessions() {
      try {
        // ?days=N is the server-side window (round 16); 0/absent means
        // "everything", which keeps the 5s poll payload unchanged.
        const days = parseInt(this.daysFilter, 10)
        const path = days > 0 ? '/api/sessions?days=' + days : '/api/sessions'
        const data = await api.get(path)
        this.sessions = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to load sessions: ' + e.message)
      } finally {
        this.loading = false
      }
    },
    async toggleExpand(id) {
      if (this.expanded === id) {
        this.expanded = null
        this.tasks = []
        this.hasMoreTasks = false
        this.taskCursor = null
        return
      }
      this.expanded = id
      this.tasks = []
      this.hasMoreTasks = false
      this.taskCursor = null
      await this.fetchTasksPage(id, null)
    },
    async fetchTasksPage(id, cursor) {
      try {
        // GET /api/sessions/:id -> { session, tasks, has_more, next_page }.
        // Without a cursor the server answers with the newest page exactly
        // like the pre-pagination handler (default 100).
        let path = '/api/sessions/' + encodeURIComponent(id)
        if (cursor) {
          // encodeURIComponent, not qs: the cursor is opaque stored text
          // containing spaces and '+' — both must survive the query intact.
          path += '?before=' + encodeURIComponent(cursor.before) +
            '&before_id=' + encodeURIComponent(cursor.beforeId)
        }
        const data = await api.get(path)
        const rows = (data && Array.isArray(data.tasks)) ? data.tasks : []
        if (cursor) {
          this.tasks = this.tasks.concat(rows)
        } else {
          this.tasks = rows
        }
        this.hasMoreTasks = !!(data && data.has_more)
        if (data && data.has_more && data.next_page) {
          this.taskCursor = {
            before: data.next_page.before || '',
            beforeId: data.next_page.before_id || '',
          }
        } else {
          this.taskCursor = null
        }
      } catch (e) {
        if (!e.expired) notify.error('Failed to load tasks: ' + e.message)
      }
    },
    loadMoreTasks() {
      if (!this.expanded || !this.taskCursor || this.loadingMore) return
      this.loadingMore = true
      this.fetchTasksPage(this.expanded, this.taskCursor).finally(() => {
        this.loadingMore = false
      })
    },
    async kill(s) {
      this.pendingKill = s
    },
    async doKill() {
      const s = this.pendingKill
      if (!s || this.acting) return
      this.acting = true
      try {
        await api.del('/api/sessions/' + encodeURIComponent(s.ID))
        notify.ok('Session killed')
        if (this.expanded === s.ID) {
          this.expanded = null
          this.tasks = []
        }
        this.pendingKill = null
        this.fetchSessions()
      } catch (e) {
        if (!e.expired) notify.error('Kill failed: ' + e.message)
      } finally {
        this.acting = false
      }
    },
    async purge(s) {
      this.pendingPurge = s
    },
    async doPurge() {
      const s = this.pendingPurge
      if (!s || this.acting) return
      this.acting = true
      try {
        // DELETE /api/sessions/:id?purge=true — hard delete (tasks + loot included)
        await api.del('/api/sessions/' + encodeURIComponent(s.ID) + '?purge=true')
        notify.ok('Session purged')
        if (this.expanded === s.ID) {
          this.expanded = null
          this.tasks = []
        }
        this.pendingPurge = null
        this.fetchSessions()
      } catch (e) {
        if (!e.expired) notify.error('Purge failed: ' + e.message)
      } finally {
        this.acting = false
      }
    },
    async openNotes(s) {
      this.notesFor = s
      this.noteDraft = ''
      this.notes = []
      try {
        const data = await api.get('/api/notes?session_id=' + encodeURIComponent(s.ID))
        this.notes = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to load notes: ' + e.message)
      }
    },
    closeNotes() {
      this.notesFor = null
    },
    async addNote() {
      const content = this.noteDraft.trim()
      if (!content || !this.notesFor) return
      this.savingNote = true
      try {
        // POST /api/notes { session_id, content }
        await api.post('/api/notes', { session_id: this.notesFor.ID, content })
        this.noteDraft = ''
        notify.ok('Note added')
        const data = await api.get('/api/notes?session_id=' + encodeURIComponent(this.notesFor.ID))
        this.notes = Array.isArray(data) ? data : []
      } catch (e) {
        if (!e.expired) notify.error('Failed to save note: ' + e.message)
      } finally {
        this.savingNote = false
      }
    },
  },
}
</script>

<style scoped>
.filters {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
}
.filter-select { width: 160px; flex-shrink: 0; }
.filter-select + .filter-select { width: 140px; }

.expand-cell { color: var(--faint); }
.transport { font-size: 12px; color: var(--muted); }
.chev {
  display: inline-block;
  transition: transform var(--speed);
  font-size: 14px;
}
.chev.open { transform: rotate(90deg); }
.fw { font-weight: 600; }
.actions-cell { white-space: nowrap; }

.loading-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
}

.detail { margin-top: 16px; }
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px 20px;
  margin-bottom: 22px;
}
.detail-item label {
  display: block;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  font-family: var(--mono);
  color: var(--faint);
  margin-bottom: 3px;
}
.detail-item code,
.detail-item span,
.detail-item .status-pill {
  font-size: 13px;
  word-break: break-all;
}
.detail-item code { font-family: var(--mono); }

.section-title {
  font-size: 13px;
  margin-bottom: 10px;
  color: var(--muted);
}
.task-list { display: flex; flex-direction: column; gap: 10px; max-height: 320px; overflow-y: auto; }
.task-cmd { font-size: 12.5px; color: var(--accent); margin-bottom: 4px; word-break: break-word; }
.task-output {
  background: var(--bg);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  font-size: 12px;
  line-height: 1.5;
  max-height: 180px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--muted);
}
.task-pending { font-style: italic; }
.load-more {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 10px;
}

/* notes modal */
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 24px;
}
.modal {
  width: 100%;
  max-width: 520px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  max-height: 80vh;
  display: flex;
  flex-direction: column;
}
.modal-body { overflow-y: auto; }
.notes-list { display: flex; flex-direction: column; gap: 10px; margin-bottom: 16px; }
.note-row {
  background: var(--surface-2);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
}
.note-content { font-size: 13px; white-space: pre-wrap; word-break: break-word; }
.note-form { display: flex; flex-direction: column; gap: 10px; align-items: flex-end; }

@media (max-width: 640px) {
  .filters { flex-direction: column; }
  .filter-select, .filter-select + .filter-select { width: 100%; }
}
</style>
