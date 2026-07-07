// WORLDC2 C2 - Notification System
// Simple toast notification system for the dashboard

const toasts = []
let container = null

function getContainer() {
  if (!container) {
    container = document.createElement('div')
    container.id = 'worldc2-toasts'
    container.style.cssText = `
      position: fixed; top: 16px; right: 16px; z-index: 9999;
      display: flex; flex-direction: column; gap: 8px; max-width: 360px;
    `
    document.body.appendChild(container)
  }
  return container
}

function createToast(message, type = 'info', duration = 4000) {
  const toast = document.createElement('div')
  const colors = {
    success: { bg: '#ecfdf5', border: '#10b981', text: '#065f46', icon: '✓' },
    error: { bg: '#fef2f2', border: '#ef4444', text: '#991b1b', icon: '✗' },
    warning: { bg: '#fffbeb', border: '#f59e0b', text: '#92400e', icon: '⚠' },
    info: { bg: '#eff6ff', border: '#3b82f6', text: '#1e40af', icon: 'ℹ' },
  }
  const c = colors[type] || colors.info

  toast.style.cssText = `
    background: ${c.bg}; border-left: 4px solid ${c.border};
    padding: 12px 16px; border-radius: 6px; color: ${c.text};
    font-size: 13px; font-family: 'Inter', sans-serif;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    animation: slideIn 0.3s ease; display: flex; align-items: center; gap: 8px;
  `
  toast.innerHTML = `<span style="font-weight:700">${c.icon}</span><span>${message}</span>`

  getContainer().appendChild(toast)
  toasts.push(toast)

  // Auto remove
  setTimeout(() => removeToast(toast), duration)

  return toast
}

function removeToast(toast) {
  if (toast.parentNode) {
    toast.style.animation = 'slideOut 0.3s ease'
    setTimeout(() => toast.parentNode?.removeChild(toast), 300)
  }
}

// Add CSS animations
const style = document.createElement('style')
style.textContent = `
  @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
`
document.head.appendChild(style)

// Export API
window.WORLDC2 = window.WORLDC2 || {}
window.WORLDC2.notify = {
  success: (msg, dur) => createToast(msg, 'success', dur),
  error: (msg, dur) => createToast(msg, 'error', dur),
  warning: (msg, dur) => createToast(msg, 'warning', dur),
  info: (msg, dur) => createToast(msg, 'info', dur),
}
