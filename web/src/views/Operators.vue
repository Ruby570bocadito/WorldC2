<template>
  <div class="operators">
    <div class="page-head">
      <div>
        <h1 class="page-title">Operators</h1>
        <p class="page-sub">Accounts with access to this console · admin only</p>
      </div>
      <button class="btn btn-primary" type="button" @click="formOpen = !formOpen">
        <IconPlus :size="15" />
        <span>{{ formOpen ? 'Close' : 'New operator' }}</span>
      </button>
    </div>

    <div v-if="formOpen" class="panel add-panel">
      <div class="panel-head">
        <span class="panel-title">Create operator</span>
      </div>
      <form class="panel-body add-form" @submit.prevent="create">
        <div class="add-grid">
          <div>
            <label class="field-label" for="op-user">Username</label>
            <input id="op-user" v-model="form.username" class="input mono" type="text" required autocomplete="off" />
          </div>
          <div>
            <label class="field-label" for="op-pass">Password</label>
            <input id="op-pass" v-model="form.password" class="input mono" type="password" required autocomplete="new-password" />
          </div>
          <div>
            <label class="field-label" for="op-role">Role</label>
            <select id="op-role" v-model="form.role" class="select">
              <option value="operator">operator</option>
              <option value="admin">admin</option>
              <option value="viewer">viewer</option>
            </select>
          </div>
        </div>
        <div class="add-actions">
          <button class="btn btn-primary" type="submit" :disabled="creating">
            {{ creating ? 'Creating…' : 'Create operator' }}
          </button>
        </div>
      </form>
    </div>

    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Created</th>
            <th style="width: 90px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="op in operators" :key="op.id">
            <td class="mono fw">{{ op.username }}</td>
            <td>
              <span class="badge" :class="roleClass(op.role)">
                {{ op.role || 'operator' }}
              </span>
            </td>
            <td class="num">{{ fmtDate(op.created_at) }}</td>
            <td>
              <button
                v-if="op.username !== currentUser"
                class="icon-btn danger"
                type="button"
                :title="'Delete ' + op.username"
                aria-label="Delete operator"
                @click="remove(op)"
              >
                <IconTrash :size="15" />
              </button>
              <span v-else class="small faint">you</span>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && !operators.length" class="empty-state">
        <IconOperators :size="30" />
        <span class="empty-title">No operators found</span>
        <span class="empty-hint">Create the first account above</span>
      </div>
      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        <span class="muted small">Loading operators…</span>
      </div>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { fmtDate } from '../utils/format.js'
import { IconPlus, IconTrash, IconOperators } from '../components/icons.js'

export default {
  name: 'OperatorsView',
  components: { IconPlus, IconTrash, IconOperators },
  data() {
    return {
      operators: [],
      form: { username: '', password: '', role: 'operator' },
      formOpen: false,
      creating: false,
      loading: true,
      currentUser: '',
    }
  },
  mounted() {
    this.currentUser = localStorage.getItem('bty_user') || ''
    this.fetchOperators()
  },
  methods: {
    fmtDate,
    roleClass(role) {
      if (role === 'admin') return 'badge-danger'
      if (role === 'viewer') return ''
      return 'badge-accent'
    },
    async fetchOperators() {
      try {
        const data = await api.get('/api/operators')
        this.operators = Array.isArray(data) ? data : []
      } catch (e) {
        if (e.status === 403) {
          notify.error('Admin access required')
        } else if (!e.expired) {
          notify.error('Failed to load operators: ' + e.message)
        }
      } finally {
        this.loading = false
      }
    },
    async create() {
      if (this.creating) return
      this.creating = true
      try {
        // POST /api/operators { username, password, role }
        await api.post('/api/operators', { ...this.form })
        notify.ok('Operator "' + this.form.username + '" created')
        this.form = { username: '', password: '', role: 'operator' }
        this.formOpen = false
        this.fetchOperators()
      } catch (e) {
        if (!e.expired) notify.error(e.status === 409 ? 'Username already exists' : 'Create failed: ' + e.message)
      } finally {
        this.creating = false
      }
    },
    async remove(op) {
      const ok = window.confirm('Delete operator "' + op.username + '"?')
      if (!ok) return
      try {
        // DELETE /api/operators/:id
        await api.del('/api/operators/' + encodeURIComponent(op.id))
        notify.ok('Operator deleted')
        this.fetchOperators()
      } catch (e) {
        if (!e.expired) notify.error('Delete failed: ' + e.message)
      }
    },
  },
}
</script>

<style scoped>
.operators { max-width: 900px; }

.add-panel { margin-bottom: 16px; }
.add-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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
