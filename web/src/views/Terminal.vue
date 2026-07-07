<template>
  <div class="terminal-view">
    <div class="terminal-header">
      <h3>Web Terminal</h3>
      <div class="terminal-controls">
        <select v-model="selectedAgent" class="agent-select">
          <option value="">Select Agent...</option>
          <option v-for="agent in agents" :key="agent.ID" :value="agent.ID">
            {{ agent.Hostname }} ({{ agent.OS }})
          </option>
        </select>
        <button @click="clearTerminal" class="btn-clear">Clear</button>
        <button @click="disconnect" class="btn-disconnect" v-if="connected">Disconnect</button>
      </div>
    </div>

    <div class="terminal-body" ref="terminalBody">
      <div v-for="(line, idx) in output" :key="idx" :class="['line', line.type]">
        <span v-if="line.type === 'prompt'" class="prompt">{{ line.prefix }}</span>
        <span class="content">{{ line.text }}</span>
      </div>
      <div v-if="connecting" class="line info">
        <span class="content">Connecting...</span>
      </div>
    </div>

    <div class="terminal-input">
      <span class="prompt-label">$</span>
      <input
        ref="input"
        v-model="command"
        @keyup.enter="execute"
        @keydown="handleKeydown"
        :disabled="!connected || !selectedAgent"
        placeholder="Type command..."
        autofocus
      />
      <button @click="execute" :disabled="!connected || !command.trim()">Send</button>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      agents: [],
      selectedAgent: '',
      command: '',
      output: [],
      connected: false,
      connecting: false,
      commandHistory: [],
      historyIndex: -1,
    }
  },
  mounted() {
    this.loadAgents()
    this.$refs.input?.focus()
  },
  methods: {
    auth() {
      const t = sessionStorage.getItem('bty_token')
      return t ? { Authorization: 'Bearer ' + t } : {}
    },
    async loadAgents() {
      try {
        const r = await fetch('/api/sessions', { headers: this.auth() })
        if (r.status === 401) { this.$router.push('/login'); return }
        if (r.ok) this.agents = await r.json()
      } catch (e) {
        console.error('Failed to load agents:', e)
      }
    },
    async execute() {
      if (!this.command.trim() || !this.selectedAgent) return

      const cmd = this.command.trim()
      this.command = ''
      this.commandHistory.unshift(cmd)
      if (this.commandHistory.length > 50) this.commandHistory.pop()
      this.historyIndex = -1

      this.output.push({ type: 'prompt', prefix: `${this.selectedAgent.slice(0,8)}> `, text: cmd })

      try {
        const r = await fetch('/api/cmd', {
          method: 'POST',
          headers: { ...this.auth(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ agent_id: this.selectedAgent, command: cmd, timeout: 30 }),
        })
        const result = await r.json()

        if (result.success) {
          const lines = (result.output || '').split('\n')
          lines.forEach(line => {
            this.output.push({ type: 'output', text: line })
          })
        } else {
          this.output.push({ type: 'error', text: result.error_message || result.error || 'Command failed' })
        }
      } catch (e) {
        this.output.push({ type: 'error', text: `Network error: ${e.message}` })
      }

      this.connected = true
      this.scrollToBottom()
    },
    clearTerminal() {
      this.output = []
    },
    disconnect() {
      this.connected = false
      this.selectedAgent = ''
      this.output.push({ type: 'info', text: 'Disconnected' })
    },
    scrollToBottom() {
      this.$nextTick(() => {
        const el = this.$refs.terminalBody
        if (el) el.scrollTop = el.scrollHeight
      })
    },
    handleKeydown(e) {
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        if (this.historyIndex < this.commandHistory.length - 1) {
          this.historyIndex++
          this.command = this.commandHistory[this.historyIndex]
        }
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        if (this.historyIndex > 0) {
          this.historyIndex--
          this.command = this.commandHistory[this.historyIndex]
        } else {
          this.historyIndex = -1
          this.command = ''
        }
      }
    }
  },
  watch: {
    selectedAgent() {
      if (this.selectedAgent) {
        this.connected = true
        this.output.push({ type: 'info', text: `Connected to ${this.selectedAgent.slice(0,8)}` })
      }
    }
  }
}
</script>

<style scoped>
.terminal-view {
  background: #1a1b26;
  border-radius: 8px;
  overflow: hidden;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  height: 500px;
  display: flex;
  flex-direction: column;
}

.terminal-header {
  background: #16161e;
  padding: 12px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #292e42;
}

.terminal-header h3 {
  color: #a9b1d6;
  font-size: 14px;
  margin: 0;
}

.terminal-controls {
  display: flex;
  gap: 8px;
  align-items: center;
}

.agent-select {
  background: #1a1b26;
  color: #a9b1d6;
  border: 1px solid #292e42;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.btn-clear, .btn-disconnect {
  background: #292e42;
  color: #a9b1d6;
  border: none;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
}

.btn-disconnect {
  background: #f7768e;
  color: #1a1b26;
}

.terminal-body {
  flex: 1;
  overflow-y: auto;
  padding: 12px 16px;
  font-size: 13px;
  line-height: 1.5;
}

.line {
  white-space: pre-wrap;
  word-break: break-all;
}

.line .prompt {
  color: #7aa2f7;
  font-weight: bold;
}

.line .content {
  color: #a9b1d6;
}

.line.output .content {
  color: #9ece6a;
}

.line.error .content {
  color: #f7768e;
}

.line.info .content {
  color: #e0af68;
  font-style: italic;
}

.terminal-input {
  display: flex;
  align-items: center;
  padding: 8px 16px;
  background: #16161e;
  border-top: 1px solid #292e42;
}

.prompt-label {
  color: #7aa2f7;
  font-weight: bold;
  margin-right: 8px;
}

.terminal-input input {
  flex: 1;
  background: transparent;
  border: none;
  color: #a9b1d6;
  font-family: inherit;
  font-size: 13px;
  outline: none;
}

.terminal-input input:disabled {
  color: #565a6e;
}

.terminal-input button {
  background: #7aa2f7;
  color: #1a1b26;
  border: none;
  padding: 6px 16px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
}

.terminal-input button:disabled {
  opacity: 0.3;
  cursor: not-allowed;
}
</style>
