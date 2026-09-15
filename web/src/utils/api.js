// WorldC2 — unified API layer.
// Every view must go through this module: it attaches the Bearer token,
// refreshes it once on 401 (queueing concurrent requests) and redirects
// to /login when the session cannot be recovered.

const TOKEN_KEY = 'bty_token'
const REFRESH_KEY = 'bty_refresh'
const EXPIRES_KEY = 'bty_expires'
const USER_KEY = 'bty_user'
const ROLE_KEY = 'bty_role'

// ---------- auth storage (localStorage) ----------

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_KEY) || ''
}

export function getAuthUser() {
  return localStorage.getItem(USER_KEY) || ''
}

export function getAuthRole() {
  return localStorage.getItem(ROLE_KEY) || ''
}

export function isAuthed() {
  return !!getToken()
}

/**
 * Persist credentials returned by POST /api/login.
 * Shape: { token, refresh_token, expires_in, user, role }
 */
export function setAuth(data) {
  if (!data || !data.token) return
  localStorage.setItem(TOKEN_KEY, data.token)
  if (data.refresh_token) localStorage.setItem(REFRESH_KEY, data.refresh_token)
  if (data.user) localStorage.setItem(USER_KEY, data.user)
  if (data.role) localStorage.setItem(ROLE_KEY, data.role)
  const expiresIn = Number(data.expires_in) || 43200
  localStorage.setItem(EXPIRES_KEY, String(Date.now() + expiresIn * 1000))
}

export function clearAuth() {
  ;[TOKEN_KEY, REFRESH_KEY, EXPIRES_KEY, USER_KEY, ROLE_KEY].forEach((k) =>
    localStorage.removeItem(k)
  )
}

// ---------- refresh coordination (single flight + queue) ----------

let refreshPromise = null

async function doRefresh() {
  const refreshToken = getRefreshToken()
  if (!refreshToken) return null
  try {
    const res = await fetch('/api/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) return null
    const data = await res.json().catch(() => null)
    if (!data || !data.token) return null
    localStorage.setItem(TOKEN_KEY, data.token)
    // Rotation: the server consumed the presented refresh token and issues a
    // replacement on every refresh — persist it or the next refresh replays
    // a consumed token and gets denied.
    if (data.refresh_token) localStorage.setItem(REFRESH_KEY, data.refresh_token)
    const expiresIn = Number(data.expires_in) || 43200
    localStorage.setItem(EXPIRES_KEY, String(Date.now() + expiresIn * 1000))
    return data.token
  } catch {
    return null
  }
}

/**
 * Refresh the access token. Concurrent callers share one request.
 * Resolves with the new token, or null when the refresh fails.
 */
function refreshAccessToken() {
  if (!refreshPromise) {
    refreshPromise = doRefresh().finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}

function redirectToLogin() {
  clearAuth()
  // Full navigation keeps things simple and drops all SPA state.
  if (!window.location.pathname.startsWith('/login')) {
    window.location.assign('/login')
  }
}

// ---------- core fetch wrapper ----------

/**
 * fetch() wrapper:
 *  - injects `Authorization: Bearer <bty_token>` from localStorage
 *  - JSON-serializes plain-object bodies and sets Content-Type
 *  - on 401, refreshes the access token once and replays the request
 *  - redirects to /login when the refresh fails
 * Resolves with the raw Response in every other case.
 */
export async function apiFetch(path, options = {}) {
  const opts = { ...options }
  const headers = new Headers(opts.headers || {})
  const token = getToken()
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', 'Bearer ' + token)
  }
  if (opts.body && typeof opts.body !== 'string' && !(opts.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
    opts.body = JSON.stringify(opts.body)
  }
  opts.headers = headers

  let res = await fetch(path, opts)

  // 401 recovery does NOT apply to /api/login: its 401s are ANSWERS
  // (invalid credentials, or totp_required asking for the second factor),
  // not expired-session signals — trying a refresh there would swallow
  // the structured response the login form needs.
  if (res.status === 401 && !opts.__retried && !path.startsWith('/api/login')) {
    const newToken = await refreshAccessToken()
    if (newToken) {
      opts.__retried = true
      headers.set('Authorization', 'Bearer ' + newToken)
      res = await fetch(path, opts)
    } else {
      redirectToLogin()
      const err = new Error('Session expired')
      err.status = 401
      err.expired = true
      throw err
    }
  }

  return res
}

/**
 * fetch wrapper that parses the body and throws typed errors.
 * Go handlers return JSON errors both as application/json and via
 * http.Error (text/plain with a JSON string body), so parse text first.
 */
export async function apiJson(path, options = {}) {
  const res = await apiFetch(path, options)
  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  if (!res.ok) {
    const message =
      (data && typeof data === 'object' && data.error) ||
      (typeof data === 'string' && data) ||
      'Request failed (HTTP ' + res.status + ')'
    const err = new Error(message)
    err.status = res.status
    err.data = data
    throw err
  }
  return data
}

export const api = {
  get: (path) => apiJson(path),
  post: (path, body) => apiJson(path, { method: 'POST', body }),
  del: (path) => apiJson(path, { method: 'DELETE' }),
  raw: apiFetch,
}

/**
 * Download a protected file: fetches with Bearer auth and saves as a blob.
 */
export async function downloadFile(path, fallbackName = 'download') {
  const res = await apiFetch(path)
  if (!res.ok) {
    if (res.status === 401) redirectToLogin()
    throw new Error('Download failed (HTTP ' + res.status + ')')
  }
  const blob = await res.blob()
  const disposition = res.headers.get('Content-Disposition') || ''
  const match = /filename="?([^";]+)"?/i.exec(disposition)
  const name = match ? match[1] : fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
