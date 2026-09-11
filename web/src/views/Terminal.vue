<template>
  <div class="runner">
    <div class="page-head">
      <div>
        <h1 class="page-title">Command Runner</h1>
        <p class="page-sub">Execute commands on a selected agent via the C2 task queue</p>
      </div>
      <span class="badge" :class="statusClass">
        <span class="dot" :class="statusDot" />
        {{ statusLabel }}
      </span>
    </div>

    <div class="runner-toolbar">
      <select v-model="selectedId" class="select runner-select" aria-label="Target session">
        <option value="" disabled>Select a session…</option>
        <option v-for="s in activeSessions" :key="s.ID" :value="s.ID">
          {{ s.Hostname || shortId(s.ID) }} · {{ s.OS || '?' }} · {{ s.Username || '?' }}
        </option>
      </select>
      <button class="btn btn-ghost" type="button" :disabled="!lines.length" @click="clear">
        <IconClose :size="14" />
        <span>Clear</span>
      </button>
    </div>

    <div class="terminal panel" role="log" aria-label="Command output">
      <div ref="scroller" class="terminal-body mono">
        <div v-if="!lines.length" class="term-hint">
          <IconTerminal :size="26" />
          <p>No commands yet.</p>
          <p class="faint">Pick an active session above and run a command.</p>
        </div>
        <div
          v-for="(l, i) in lines"
          :key="i"
          class="term-line"
          :class="'term-' + l.type"
        >
          <span v-if="l.prefix" class="term-prefix">{{ l.prefix }}</span>
          <span class="term-text">{{ l.text }}</span>
        </div>
        <div v-if="running" class="term-line term-sys">
          <span class="term-text">… awaiting agent output</span>
        </div>
      </div>

      <form class="term-input" @submit.prevent="execute">
        <span class="term-prompt mono">$</span>
        <input
          ref="cmdInput"
          v-model="command"
          class="term-field mono"
          type="text"
          :placeholder="selectedId ? 'Type a command…' : 'Select a session first'"
          :disabled="!selectedId || running"
          spellcheck="false"
          autocomplete="off"
          @keydown.up.prevent="historyUp"
          @keydown.down.prevent="historyDown"
        />
        <button class="btn btn-primary term-send" type="submit" :disabled="!selectedId || running || !command.trim()">
          {{ running ? 'Running…' : 'Run' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script>
import { api } from '../utils/api.js'
import { notify } from '../utils/notifications.js'
import { shortId } from '../utils/format.js'
import { IconTerminal, IconClose } from '../components/icons.js'

export default {
  name: 'TerminalView',
  components: { IconTerminal, IconClose },
  data() {
    return {
      sessions: [],
      selectedId: '',
      command: '',
      lines: [],
      running: false,
      authFailed: false,
      history: [],
      historyIndex: -1,
      timer: null,
    }
  },
  computed: {
    activeSessions() {
      return this.sessions.filter((s) => s.State === 'active')
    },
    hasSelection() {
      return !!this.selectedId
    },
    statusClass() {
      if (this.authFailed) return 'badge-danger'
      if (!this.hasSelection) return ''
      return 'badge-ok'
    },
    statusDot() {
      if (this.authFailed) return 'dot-danger'
      if (!this.hasSelection) return ''
      return 'dot-ok'
    },
    statusLabel() {
      if (this.authFailed) return 'unauthorized'
      if (!this.hasSelection) return 'no target'
      return 'ready'
    },
    prompt() {
      const s = this.sessions.find((x) => x.ID === this.selectedId)
      return (s && (s.Hostname || s.ID.slice(0, 8)) || 'agent') + '>'
    },
  },
  mounted() {
    this.loadSessions()
    this.timer = setInterval(() => this.loadSessions(), 5000)
  },
  beforeUnmount() {
    if (this.timer) clearInterval(this.timer)
  },
  methods: {
    shortId,
    async loadSessions() {
      try {
        const data = await api.get('/api/sessions')
        this.sessions = Array.isArray(data) ? data : []
        this.authFailed = false
        if (
          this.selectedId &&
          !this.sessions.some((s) => s.ID === this.selectedId && s.State === 'active')
        ) {
          this.pushLine('sys', 'Target session is no longer active.')
          this.selectedId = ''
        }
      } catch (e) {
        if (!e.expired) notify.error('Failed to load sessions: ' + e.message)
      }
    },
    pushLine(type, text, prefix = '') {
      this.lines.push({ type, text, prefix })
      if (this.lines.length > 500) this.lines.shift()
      this.$nextTick(() => {
        const el = this.$refs.scroller
        if (el) el.scrollTop = el.scrollHeight
      })
    },
    clear() {
      this.lines = []
    },
    historyUp() {
      if (!this.history.length) return
      const next = Math.min(this.historyIndex + 1, this.history.length - 1)
      if (next !== this.historyIndex) {
        this.historyIndex = next
        this.command = this.history[next]
      }
    },
    historyDown() {
      if (this.historyIndex <= 0) {
        this.historyIndex = -1
        this.command = ''
        return
      }
      this.historyIndex--
      this.command = this.history[this.historyIndex]
    },
    async execute() {
      const cmd = this.command.trim()
      if (!cmd || !this.selectedId || this.running) return

      this.history.unshift(cmd)
      if (this.history.length > 50) this.history.pop()
      this.historyIndex = -1

      this.pushLine('cmd', cmd, this.prompt)
      this.command = ''
      this.running = true

      try {
        // POST /api/cmd { agent_id, command, timeout } -> TaskResult
        const result = await api.post('/api/cmd', {
          agent_id: this.selectedId,
          command: cmd,
          timeout: 30,
        })
        if (result && result.success) {
          const out = result.output || result.Output || ''
          if (out) {
            String(out).split('\n').forEach((l) => this.pushLine('out', l))
          } else {
            this.pushLine('sys', '(no output)')
          }
        } else {
          const msg = (result && (result.error_message || result.error)) || 'Command failed'
          this.pushLine('err', msg)
        }
      } catch (e) {
        if (e.expired) {
          this.authFailed = true
          this.pushLine('err', '401 — session expired, redirecting to login…')
        } else {
          this.pushLine('err', (e.status ? 'HTTP ' + e.status + ' — ' : '') + (e.message || 'request failed'))
        }
      } finally {
        this.running = false
      }
    },
  },
}
</script>

<style scoped>
.runner-toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
}
.runner-select { max-width: 380px; }

.terminal {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 300px);
  min-height: 380px;
}
.terminal-body {
  flex: 1;
  overflow-y: auto;
  padding: 18px 20px;
  background: var(--bg);
  font-size: 12.5px;
  line-height: 1.6;
}

.term-hint {
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 6px;
  color: var(--faint);
  text-align: center;
}
.term-hint p { font-size: 13px; }

.term-line {
  white-space: pre-wrap;
  word-break: break-word;
}
.term-prefix {
  color: var(--accent);
  font-weight: 600;
  margin-right: 8px;
}
.term-cmd .term-text { color: var(--text); }
.term-out .term-text { color: var(--muted); }
.term-sys .term-text { color: var(--faint); font-style: italic; }
.term-err .term-text { color: var(--danger); }

.term-input {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-top: 1px solid var(--border);
  background: var(--surface);
}
.term-prompt { color: var(--accent); font-weight: 600; }
.term-field {
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text);
  font-size: 13px;
  outline: none;
}
.term-field::placeholder { color: var(--faint); }
.term-field:disabled { color: var(--faint); }
.term-send { flex-shrink: 0; }
</style>
