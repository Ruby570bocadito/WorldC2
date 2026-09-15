<template>
  <div class="modal-backdrop" @click.self="cancel">
    <div
      class="modal confirm-modal"
      role="alertdialog"
      aria-modal="true"
      :aria-label="title"
    >
      <div class="confirm-body">
        <span class="confirm-icon" :class="danger ? 'is-danger' : 'is-info'">
          <IconAlert :size="20" />
        </span>
        <h2 class="confirm-title">{{ title }}</h2>
        <p class="confirm-message">{{ message }}</p>
        <label v-if="requirePhrase" class="confirm-typebox">
          <span class="confirm-typelabel">
            Type <code>{{ requirePhrase }}</code> to confirm
          </span>
          <input
            ref="phraseInput"
            v-model="typed"
            class="input"
            type="text"
            :placeholder="requirePhrase"
            :maxlength="requirePhrase.length + 8"
            autocomplete="off"
            spellcheck="false"
          />
        </label>
      </div>
      <div class="confirm-actions">
        <button ref="cancelBtn" class="btn btn-ghost" type="button" @click="cancel">
          Cancel
        </button>
        <button
          class="btn"
          :class="danger ? 'btn-danger' : 'btn-primary'"
          type="button"
          :disabled="!canConfirm || busy"
          @click="confirm"
        >
          {{ busy ? 'Working…' : confirmLabel }}
        </button>
      </div>
    </div>
  </div>
</template>

<script>
import { IconAlert } from './icons.js'

// ConfirmModal replaces window.confirm() across the console. Reasons:
// window.confirm is a browser chrome dialog that cannot be styled, cannot
// explain WHAT will be destroyed, and in some embedded/automated contexts
// is suppressed entirely (a delete then fails silently). This component:
//  - traps the choice in a real dialog (role=alertdialog) with Esc/backdrop
//    dismissal, so accidental double-Esc can never confirm;
//  - optionally requires typing a phrase (requirePhrase) for the most
//    destructive actions — purge and bulk deletes — matching the
//    "expensive actions deserve friction" rule;
//  - keeps focus management explicit: autofocus goes to Cancel (the safe
//    choice), never to the destructive button.
export default {
  name: 'ConfirmModal',
  components: { IconAlert },
  props: {
    title: { type: String, required: true },
    message: { type: String, required: true },
    confirmLabel: { type: String, default: 'Confirm' },
    danger: { type: Boolean, default: false },
    // When set, the confirm button stays disabled until the operator
    // types this exact phrase (case-sensitive).
    requirePhrase: { type: String, default: '' },
    busy: { type: Boolean, default: false },
  },
  emits: ['confirm', 'cancel'],
  data() {
    return { typed: '' }
  },
  computed: {
    canConfirm() {
      if (!this.requirePhrase) return true
      return this.typed === this.requirePhrase
    },
  },
  mounted() {
    document.addEventListener('keydown', this.onKey)
    // Autofocus the SAFE control: cancel first, phrase input if present.
    this.$nextTick(() => {
      if (this.requirePhrase && this.$refs.phraseInput) {
        this.$refs.phraseInput.focus()
      } else if (this.$refs.cancelBtn) {
        this.$refs.cancelBtn.focus()
      }
    })
  },
  beforeUnmount() {
    document.removeEventListener('keydown', this.onKey)
  },
  methods: {
    onKey(e) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        this.cancel()
      }
    },
    cancel() {
      this.$emit('cancel')
    },
    confirm() {
      if (!this.canConfirm || this.busy) return
      this.$emit('confirm')
    },
  },
}
</script>

<style scoped>
.confirm-modal {
  max-width: 440px;
}
.confirm-body {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.confirm-icon {
  width: 34px;
  height: 34px;
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
}
.confirm-icon.is-danger {
  background: rgba(229, 72, 77, 0.14);
  color: #e5484d;
}
.confirm-icon.is-info {
  background: rgba(88, 166, 255, 0.12);
  color: var(--accent);
}
.confirm-title {
  font-size: 15px;
  font-weight: 600;
  margin: 0;
}
.confirm-message {
  font-size: 13px;
  color: var(--muted);
  line-height: 1.55;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}
.confirm-typebox {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 4px;
}
.confirm-typelabel {
  font-size: 12px;
  color: var(--muted);
}
.confirm-typelabel code {
  font-family: var(--mono);
  color: var(--accent);
  background: var(--surface-2);
  padding: 1px 5px;
  border-radius: 4px;
}
.confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  padding: 14px 20px;
  border-top: 1px solid var(--border-soft);
}
</style>
