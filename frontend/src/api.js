// Appels REST vers le backend (.NET). En prod, nginx relaie /api -> backend:8080.
import { useCallback, useEffect, useState } from 'react'

const BASE = import.meta.env.VITE_API_URL ?? ''

export function qs(params) {
  const p = new URLSearchParams()
  Object.entries(params ?? {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '' && v !== false) p.append(k, v)
  })
  const s = p.toString()
  return s ? `?${s}` : ''
}

async function request(path, options = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  })
  if (!res.ok) {
    let msg
    try {
      const j = await res.json()
      msg = j.error ?? j.title ?? j.message
    } catch { /* corps vide */ }
    throw new Error(msg || `${res.status} ${res.statusText}`)
  }
  if (res.status === 204) return null
  const ct = res.headers.get('content-type') ?? ''
  return ct.includes('json') ? res.json() : res.text()
}

export const api = {
  dashboard: (days = 30) => request(`/api/dashboard${qs({ days })}`),

  vulnerabilities: (q) => request(`/api/vulnerabilities${qs(q)}`),
  vulnerabilitiesNew: (q) => request(`/api/vulnerabilities/new${qs(q)}`),
  vulnerability: (id) => request(`/api/vulnerabilities/${id}`),
  exportUrl: (q) => `${BASE}/api/vulnerabilities/export${qs(q)}`,
  resetVulnerabilities: () => request('/api/vulnerabilities/reset', { method: 'POST' }),

  technologies: () => request('/api/technologies'),
  technologyExportUrl: () => `${BASE}/api/technologies/export`,
  technologyMeta: () => request('/api/technologies/meta'),
  technologyUpdates: () => request('/api/technologies/updates'),
  normalize: (line) => request(`/api/technologies/normalize${qs({ line })}`),
  createTechnology: (t) => request('/api/technologies', { method: 'POST', body: t }),
  updateTechnology: (id, t) => request(`/api/technologies/${id}`, { method: 'PUT', body: t }),
  deleteTechnology: (id) => request(`/api/technologies/${id}`, { method: 'DELETE' }),
  importTechnologies: (text, dryRun) => request('/api/technologies/import', { method: 'POST', body: { text, dryRun } }),
  rescanTechnology: (id) => request(`/api/technologies/${id}/rescan`, { method: 'POST' }),
  recorrelate: (id) => request(`/api/technologies/${id}/recorrelate`, { method: 'POST' }),

  azdoRepositories: () => request('/api/azure-devops/repositories'),
  azdoScan: (targets) => request('/api/azure-devops/scan', { method: 'POST', body: { targets } }),

  alerts: (q) => request(`/api/alerts${qs(q)}`),
  setAlertStatus: (ids, status, comment) =>
    request('/api/alerts/status', { method: 'PATCH', body: { ids, status, comment } }),

  notifications: () => request('/api/notifications'),
  notification: (id) => request(`/api/notifications/${id}`),
  testEmail: (to) => request(`/api/notifications/test${qs({ to })}`, { method: 'POST' }),
  sendNow: () => request('/api/notifications/send-now', { method: 'POST' }),

  scans: () => request('/api/scans'),
  scannerStatus: () => request('/api/scans/status'),
  triggerScan: (technologyId) => request(`/api/scans/trigger${qs({ technologyId })}`, { method: 'POST' }),
}

/** Petit hook de chargement : { data, error, loading, reload } */
export function useApi(fn, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true })
  const load = useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }))
    return fn()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error) => setState((s) => ({ ...s, error, loading: false })))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => { load() }, [load])
  return { ...state, reload: load }
}

// ---------- formatage ----------
const dtf = new Intl.DateTimeFormat('fr-CA', { dateStyle: 'medium' })
const dttf = new Intl.DateTimeFormat('fr-CA', { dateStyle: 'medium', timeStyle: 'short' })
export const fmtDate = (d) => (d ? dtf.format(new Date(d)) : '—')
export const fmtDateTime = (d) => (d ? dttf.format(new Date(d)) : '—')
export const fmtPct = (x) => (x == null ? '—' : `${(x * 100).toFixed(x < 0.01 ? 2 : 1)} %`)
