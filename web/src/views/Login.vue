<template>
  <div class="login-page">
    <div class="login-card">
      <h1 class="login-logo">WORLDC2</h1>
      <p class="login-sub">C2 Framework — ruby570bocadito</p>
      <form @submit.prevent="login" class="login-form">
        <input v-model="user" placeholder="Operator" autocomplete="off" class="input" />
        <input v-model="pass" type="password" placeholder="Passphrase" class="input" />
        <p v-if="err" class="error">{{ err }}</p>
        <button type="submit" class="btn" :disabled="loading">{{ loading ? 'Connecting...' : 'Authenticate' }}</button>
      </form>
    </div>
  </div>
</template>

<script>
export default {
  data() { return { user: '', pass: '', loading: false, err: '' } },
  methods: {
    async login() {
      this.loading = true
      this.err = ''
      try {
        const r = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: this.user, password: this.pass })
        })
        if (r.ok) {
          const data = await r.json()
          sessionStorage.setItem('bty_token', data.token)
          sessionStorage.setItem('bty_refresh', data.refresh_token)
          sessionStorage.setItem('bty_user', data.user)
          sessionStorage.setItem('bty_role', data.role)
          sessionStorage.setItem('bty_expires', Date.now() + data.expires_in * 1000)
          this.$router.push('/sessions')
        } else {
          const body = await r.json().catch(() => null)
          this.err = body?.error || 'Invalid credentials'
        }
      } catch (e) {
        this.err = 'Cannot connect to server'
      }
      this.loading = false
    }
  }
}
</script>

<style scoped>
.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8f9fa}
.login-card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:40px;width:380px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login-logo{font-family:'JetBrains Mono',monospace;font-size:32px;font-weight:700;color:#059669;text-align:center;margin-bottom:4px}
.login-sub{text-align:center;font-size:12px;color:#9ca3af;margin-bottom:28px}
.login-form{display:flex;flex-direction:column;gap:14px}
.input{width:100%;padding:10px 14px;border:1px solid #e5e7eb;border-radius:8px;font-size:14px;font-family:'JetBrains Mono',monospace;outline:none;transition:border-color .2s}
.input:focus{border-color:#059669}
.btn{width:100%;padding:12px;background:#059669;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#047857}
.btn:disabled{opacity:.5}
.error{font-size:12px;color:#ef4444;text-align:center;background:#fef2f2;padding:8px;border-radius:6px}
</style>
