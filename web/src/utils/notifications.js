// WorldC2 — toast notifications.
// Minimal dark toasts, bottom-right, auto-dismiss after 4s.
// Security: message is ALWAYS rendered via textContent — never innerHTML.

let container = null

function getContainer() {
  if (!container) {
    container = document.createElement('div')
    container.className = 'toast-stack'
    container.setAttribute('role', 'status')
    container.setAttribute('aria-live', 'polite')
    document.body.appendChild(container)
  }
  return container
}

function dismiss(toast) {
  if (!toast || !toast.parentNode) return
  toast.classList.remove('toast-in')
  toast.classList.add('toast-out')
  setTimeout(() => {
    if (toast.parentNode) toast.parentNode.removeChild(toast)
  }, 200)
}

function show(message, type = 'info', duration = 4000) {
  const stack = getContainer()

  const toast = document.createElement('div')
  toast.className = 'toast toast-' + type

  const icon = document.createElement('span')
  icon.className = 'toast-icon'
  icon.textContent = type === 'ok' ? '✓' : type === 'error' ? '✕' : 'ℹ'

  const text = document.createElement('span')
  text.className = 'toast-text'
  text.textContent = String(message) // safe by construction

  toast.appendChild(icon)
  toast.appendChild(text)

  // enter on next frame so the transition applies
  requestAnimationFrame(() => {
    requestAnimationFrame(() => toast.classList.add('toast-in'))
  })

  toast.addEventListener('click', () => dismiss(toast))
  stack.appendChild(toast)

  const timer = setTimeout(() => dismiss(toast), duration)
  toast.addEventListener('click', () => clearTimeout(timer), { once: true })

  return toast
}

export const notify = {
  info: (message, duration) => show(message, 'info', duration),
  ok: (message, duration) => show(message, 'ok', duration),
  success: (message, duration) => show(message, 'ok', duration), // alias
  error: (message, duration) => show(message, 'error', duration),
}

export default notify
