// Petits composants partagés
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const SEVERITY_LABEL = {
  CRITICAL: 'Critique',
  HIGH: 'Élevée',
  MEDIUM: 'Moyenne',
  LOW: 'Faible',
  NONE: 'Aucune',
  UNKNOWN: 'Inconnue',
}

// Icône + libellé : la couleur ne porte jamais seule l'information
const SEVERITY_ICON = { CRITICAL: '▲▲', HIGH: '▲', MEDIUM: '●', LOW: '▼', NONE: '–', UNKNOWN: '?' }

const STATUS_LABEL = {
  success: 'réussi', partial: 'partiel', failed: 'échec', running: 'en cours',
  sent: 'envoyé', pending: 'en attente',
}

export function StatusText({ value }) {
  return <span className={`status status-${value}`}>{STATUS_LABEL[value] ?? value}</span>
}

export function SeverityBadge({ value }) {
  const v = value ?? 'UNKNOWN'
  return (
    <span className={`sev sev-${v.toLowerCase()}`} title={`Criticité : ${SEVERITY_LABEL[v] ?? v}`}>
      <span aria-hidden="true" className="sev-icon">{SEVERITY_ICON[v] ?? '?'}</span>
      {SEVERITY_LABEL[v] ?? v}
    </span>
  )
}

export function KevBadge({ due }) {
  return (
    <span className="kev" title="Catalogue CISA KEV : faille exploitée activement">
      KEV{due ? ` · ${new Date(due).toISOString().slice(0, 10)}` : ''}
    </span>
  )
}

export function Kpi({ label, value, hint, tone }) {
  return (
    <div className={`kpi ${tone ? `kpi-${tone}` : ''}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value ?? '—'}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  )
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null
  return (
    <div className="error" role="alert">
      <strong>Erreur :</strong> {error.message}
      {onRetry && <button className="btn btn-small" onClick={onRetry}>Réessayer</button>}
    </div>
  )
}

export function Loading({ show }) {
  return show ? <div className="loading">Chargement…</div> : null
}

export function Pager({ page, pageSize, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="pager">
      <span>{total} résultat{total > 1 ? 's' : ''}</span>
      <button className="btn btn-small" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹ Précédent</button>
      <span>Page {page} / {pages}</span>
      <button className="btn btn-small" disabled={page >= pages} onClick={() => onPage(page + 1)}>Suivant ›</button>
    </div>
  )
}

export function CveLink({ cveId, externalId }) {
  const id = cveId ?? externalId
  const url = cveId
    ? `https://nvd.nist.gov/vuln/detail/${cveId}`
    : id?.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${id}`
  return <a href={url} target="_blank" rel="noreferrer" className="mono">{id}</a>
}

/** Liste déroulante des solutions déclarées sur les technologies (sans doublon, casse ignorée). */
export function SolutionSelect({ techs, value, onChange }) {
  const names = [...new Map((techs ?? []).flatMap((t) => t.solutions ?? []).map((s) => [s.toLowerCase(), s])).values()]
    .sort((a, b) => a.localeCompare(b, 'fr', { sensitivity: 'base' }))
  return (
    <label>Solution
      <select value={value} onChange={onChange}>
        <option value="">Toutes</option>
        {names.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
    </label>
  )
}

export function SeverityChips({ value, onChange }) {
  const selected = value ? value.split(',') : []
  const toggle = (s) => {
    const next = selected.includes(s) ? selected.filter((x) => x !== s) : [...selected, s]
    onChange(next.join(','))
  }
  return (
    <div className="chips" role="group" aria-label="Filtrer par criticité">
      {SEVERITIES.map((s) => (
        <button key={s} type="button" aria-pressed={selected.includes(s)}
          className={`chip ${selected.includes(s) ? 'chip-on' : ''}`} onClick={() => toggle(s)}>
          <SeverityBadge value={s} />
        </button>
      ))}
    </div>
  )
}
