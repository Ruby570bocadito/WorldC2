// WorldC2 — shared formatting helpers.

export function fmtDate(value) {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function fmtAgo(value) {
  if (!value) return '—'
  const t = new Date(value).getTime()
  if (Number.isNaN(t)) return '—'
  const diff = Math.max(0, Date.now() - t)
  const s = Math.floor(diff / 1000)
  if (s < 60) return s + 's ago'
  const m = Math.floor(s / 60)
  if (m < 60) return m + 'm ago'
  const h = Math.floor(m / 60)
  if (h < 24) return h + 'h ' + (m % 60) + 'm ago'
  const d = Math.floor(h / 24)
  return d + 'd ago'
}

export function fmtSize(bytes) {
  const b = Number(bytes)
  if (!b || b <= 0) return '—'
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB'
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB'
  return b + ' B'
}

export function shortId(id, n = 10) {
  if (!id) return '—'
  return String(id).length > n ? String(id).slice(0, n) + '…' : String(id)
}

export function ipOf(s) {
  return (s && (s.PublicIP || s.LocalIP)) || '—'
}
