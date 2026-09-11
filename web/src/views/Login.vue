<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-brand">
        <IconShield :size="26" class="login-shield" />
        <h1 class="login-logo">WorldC2</h1>
        <p class="login-sub">C2 operator console · authorized use only</p>
      </div>

      <form class="login-form" @submit.prevent="login">
        <div class="field">
          <label class="field-label" for="login-user">Operator</label>
          <input
            id="login-user"
            v-model="username"
            class="input mono"
            type="text"
            autocomplete="username"
            spellcheck="false"
            required
          />
        </div>

        <div class="field">
          <label class="field-label" for="login-pass">Passphrase</label>
          <input
            id="login-pass"
            v-model="password"
            class="input mono"
            type="password"
            autocomplete="current-password"
            required
          />
        </div>

        <p v-if="error" class="login-error" role="alert">{{ error }}</p>

        <button class="btn btn-primary login-btn" type="submit" :disabled="loading">
          <span v-if="loading" class="spinner" />
          <span>{{ loading ? 'Authenticating…' : 'Authenticate' }}</span>
        </button>
      </form>
    </div>

    <p class="login-foot">WorldC2 Framework · lab environment</p>
  </div>
</template>

<script>
import { IconShield } from '../components/icons.js'
import { api, setAuth } from '../utils/api.js'

export default {
  name: 'LoginView',
  components: { IconShield },
  data() {
    return {
      username: '',
      password: '',
      loading: false,
      error: '',
    }
  },
  methods: {
    async login() {
      if (this.loading) return
      this.loading = true
      this.error = ''
      try {
        // POST /api/login -> { token, refresh_token, expires_in, user, role }
        const data = await api.post('/api/login', {
          username: this.username,
          password: this.password,
        })
        setAuth(data) // stores bty_token, bty_refresh and computes bty_expires
        this.$router.push('/')
      } catch (e) {
        this.error =
          e.status === 401
            ? 'Invalid credentials'
            : e.message || 'Cannot reach the C2 server'
      } finally {
        this.loading = false
      }
    },
  },
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 24px;
  padding: 24px;
  background: var(--bg);
}

.login-card {
  width: 100%;
  max-width: 380px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 36px 32px 32px;
}

.login-brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  margin-bottom: 28px;
}
.login-shield { color: var(--accent); }
.login-logo {
  font-family: var(--mono);
  font-size: 26px;
  font-weight: 700;
  letter-spacing: -0.03em;
}
.login-sub {
  font-size: 12px;
  color: var(--muted);
  text-align: center;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.login-error {
  font-size: 12.5px;
  color: var(--danger);
  background: var(--danger-soft);
  border: 1px solid rgba(229, 72, 77, 0.35);
  border-radius: var(--radius-sm);
  padding: 9px 12px;
  text-align: center;
}

.login-btn {
  width: 100%;
  height: 40px;
  margin-top: 4px;
}

.login-foot {
  font-size: 12px;
  color: var(--faint);
}
</style>
