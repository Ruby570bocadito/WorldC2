<template>
  <div class="operators-view">
    <h2>Operators Management</h2>
    <p class="subtitle">Manage C2 operator accounts and permissions</p>

    <div class="add-operator-form">
      <h3>Add New Operator</h3>
      <form @submit.prevent="addOperator">
        <div class="form-row">
          <input v-model="newOp.username" placeholder="Username" required />
          <input v-model="newOp.password" type="password" placeholder="Password" required />
          <select v-model="newOp.role">
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
          <button type="submit" :disabled="loading">
            {{ loading ? 'Adding...' : 'Add Operator' }}
          </button>
        </div>
      </form>
    </div>

    <div class="operators-list" v-if="operators.length">
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="op in operators" :key="op.id">
            <td>{{ op.username }}</td>
            <td>
              <span :class="['role-badge', op.role]">{{ op.role }}</span>
            </td>
            <td>{{ formatDate(op.created_at) }}</td>
            <td>
              <button v-if="op.username !== currentUser" @click="deleteOperator(op.id)" class="btn-danger">
                Delete
              </button>
              <span v-else class="current-badge">Current</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-else class="empty-state">
      <p>No operators found</p>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      operators: [],
      newOp: { username: '', password: '', role: 'operator' },
      loading: false,
      currentUser: null,
    }
  },
  mounted() {
    this.loadOperators()
    this.currentUser = sessionStorage.getItem('bty_user') || 'admin'
  },
  methods: {
    auth() {
      const t = sessionStorage.getItem('bty_token')
      return t ? { Authorization: 'Bearer ' + t } : {}
    },
    async loadOperators() {
      try {
        const r = await fetch('/api/operators', { headers: this.auth() })
        if (r.status === 401) { this.$router.push('/login'); return }
        if (r.ok) this.operators = await r.json()
      } catch (e) {
        console.error('Failed to load operators:', e)
      }
    },
    async addOperator() {
      this.loading = true
      try {
        const r = await fetch('/api/operators', {
          method: 'POST',
          headers: { ...this.auth(), 'Content-Type': 'application/json' },
          body: JSON.stringify(this.newOp),
        })
        if (r.ok) {
          this.newOp = { username: '', password: '', role: 'operator' }
          this.loadOperators()
          if (window.WORLDC2?.notify) window.WORLDC2.notify.success('Operator added')
        } else {
          if (window.WORLDC2?.notify) window.WORLDC2.notify.error('Failed to add operator')
        }
      } catch (e) {
        if (window.WORLDC2?.notify) window.WORLDC2.notify.error('Network error')
      }
      this.loading = false
    },
    async deleteOperator(id) {
      if (!confirm('Delete this operator?')) return
      try {
        const r = await fetch(`/api/operators/${id}`, { method: 'DELETE', headers: this.auth() })
        if (r.ok) {
          this.loadOperators()
          if (window.WORLDC2?.notify) window.WORLDC2.notify.success('Operator deleted')
        }
      } catch (e) {
        if (window.WORLDC2?.notify) window.WORLDC2.notify.error('Failed to delete')
      }
    },
    formatDate(dateStr) {
      if (!dateStr) return 'Unknown'
      return new Date(dateStr).toLocaleDateString()
    },
  },
}
</script>

<style scoped>
.operators-view { max-width: 800px; margin: 0 auto; }
h2 { font-size: 24px; margin-bottom: 4px; }
.subtitle { color: #6b7280; margin-bottom: 24px; }

.add-operator-form {
  background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
  padding: 20px; margin-bottom: 24px;
}
.add-operator-form h3 { font-size: 16px; margin-bottom: 12px; }
.form-row { display: flex; gap: 12px; }
.form-row input, .form-row select {
  padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px;
  font-size: 14px; flex: 1;
}
.form-row button {
  padding: 8px 20px; background: #059669; color: #fff; border: none;
  border-radius: 6px; font-size: 14px; font-weight: 500; cursor: pointer;
  white-space: nowrap;
}
.form-row button:hover { background: #047857; }
.form-row button:disabled { opacity: 0.5; cursor: not-allowed; }

table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; }
th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #f3f4f6; }
th { background: #f9fafb; font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; }
td { font-size: 14px; }

.role-badge {
  padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;
}
.role-badge.admin { background: #fef3c7; color: #92400e; }
.role-badge.operator { background: #dbeafe; color: #1e40af; }
.role-badge.viewer { background: #f3f4f6; color: #374151; }

.btn-danger {
  padding: 4px 12px; background: #fee2e2; color: #dc2626; border: none;
  border-radius: 4px; font-size: 12px; cursor: pointer;
}
.btn-danger:hover { background: #fecaca; }
.current-badge { font-size: 12px; color: #059669; font-weight: 500; }

.empty-state { text-align: center; padding: 40px; color: #9ca3af; }
</style>
