import { useMemo, useState } from 'react'
import { api, fmtDateTime, useApi } from '../api'
import { ErrorBox, Loading, SeverityBadge } from '../components/ui'
import AzureDevOpsImport from '../components/AzureDevOpsImport'

const EMPTY = { name: '', type: 'other', version: '', vendor: '', product: '', ecosystem: '', packageName: '', cpe: '', keywords: '', solutions: '', notes: '', isActive: true }
const NO_SOLUTION = 'Sans solution'
const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1 }

// Préférences d'affichage propres au navigateur (le stockage peut être indisponible)
const store = {
  get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v) } catch { return d } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)) } catch { /* ignoré */ } },
}

const splitSolutions = (s) => s.split(',').map((x) => x.trim()).filter(Boolean)

/** Groupes { name, items } : une technologie partagée figure dans chaque solution, « Sans solution » en dernier. */
function groupBySolution(techs) {
  const groups = new Map()
  for (const t of techs) {
    for (const s of t.solutions.length ? t.solutions : [NO_SOLUTION]) {
      const key = s.toLowerCase()
      if (!groups.has(key)) groups.set(key, { name: s, items: [] })
      groups.get(key).items.push(t)
    }
  }
  return [...groups.values()].sort((a, b) =>
    (a.name === NO_SOLUTION) - (b.name === NO_SOLUTION) || a.name.localeCompare(b.name, 'fr', { sensitivity: 'base' }))
}

function groupStats(items) {
  const open = items.reduce((n, t) => n + t.openAlertCount, 0)
  const max = items.reduce((m, t) => ((SEVERITY_RANK[t.maxSeverity] ?? 0) > (SEVERITY_RANK[m] ?? 0) ? t.maxSeverity : m), null)
  return { open, max, never: items.filter((t) => !t.lastScannedAt).length, inactive: items.filter((t) => !t.isActive).length }
}
const TYPE_LABEL = {
  os: 'Système', framework: 'Framework', runtime: 'Runtime', library: 'Bibliothèque', database: 'Base de données',
  webserver: 'Serveur web', docker_image: 'Image Docker', application: 'Application', other: 'Autre',
}
const IMPORT_EXAMPLE = `# Une technologie par ligne : [préfixe:]nom[@version] [| option=valeur]
# [Solution] : les lignes suivantes appartiennent à cette solution
[Ma solution]
os:Ubuntu@22.04
framework:ASP.NET Core@8.0.8
runtime:PHP 8.1.2
npm:react@18.2.0
nuget:Newtonsoft.Json@13.0.1
docker:postgres:16.3-alpine
lib:MaLib@2.1 | cpe=cpe:2.3:a:monvendeur:malib:*:*:*:*:*:*:*:*`

export default function Technologies() {
  const { data, error, loading, reload } = useApi(() => api.technologies(), [])
  const meta = useApi(() => api.technologyMeta(), [])
  const [form, setForm] = useState(null) // null = fermé ; {id?, ...}
  const [importText, setImportText] = useState('')
  const [preview, setPreview] = useState(null)
  const [azdo, setAzdo] = useState(false)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)
  const [grouped, setGrouped] = useState(() => store.get('stack.grouped', true))
  const [collapsed, setCollapsed] = useState(() => store.get('stack.collapsed', []))

  const groups = useMemo(() => (data ? groupBySolution(data) : []), [data])
  const solutionNames = groups.map((g) => g.name).filter((n) => n !== NO_SOLUTION)

  const toggleGrouped = (on) => { setGrouped(on); store.set('stack.grouped', on) }
  const toggleGroup = (name) => {
    const next = collapsed.includes(name) ? collapsed.filter((n) => n !== name) : [...collapsed, name]
    setCollapsed(next); store.set('stack.collapsed', next)
  }

  const run = async (fn, ok) => {
    setBusy(true); setMsg(null)
    try { const r = await fn(); setMsg(typeof ok === 'function' ? ok(r) : ok); reload() }
    catch (e) { setMsg(`Erreur : ${e.message}`) }
    finally { setBusy(false) }
  }

  const save = (e) => {
    e.preventDefault()
    const body = { ...form, solutions: splitSolutions(form.solutions) }
    delete body.id
    run(() => (form.id ? api.updateTechnology(form.id, body) : api.createTechnology(body)), (t) =>
      `« ${t.name} » enregistrée. Corrélation faite avec les failles connues ; un scan ciblé est lancé.`)
    setForm(null)
  }

  const edit = (t) => setForm({
    id: t.id, name: t.name.replace(/ \(image Docker\)$/, ''), type: t.type, version: t.version, vendor: t.vendor, product: t.product,
    ecosystem: t.ecosystem, packageName: t.packageName ?? '', cpe: t.cpe ?? '', keywords: t.keywords ?? '',
    solutions: t.solutions.join(', '), notes: t.notes ?? '', isActive: t.isActive,
  })

  // Dans une vue groupée, `inGroup` = solution du groupe (les autres solutions sont rappelées en petit)
  const row = (t, inGroup) => {
    const others = t.solutions.filter((s) => s.toLowerCase() !== inGroup?.toLowerCase())
    return (
      <tr key={`${inGroup ?? ''}-${t.id}`} className={t.isActive ? '' : 'row-muted'}>
        <td><strong>{t.name}</strong>
          {others.length > 0 && <div className="small">{others.map((s) => <span key={s} className="tag">{inGroup ? `aussi : ${s}` : s}</span>)}</div>}
          {t.notes && <div className="muted small">{t.notes}</div>}</td>
        <td>{TYPE_LABEL[t.type] ?? t.type}</td>
        <td className="mono">{t.version || '—'}</td>
        <td className="mono small wrap">
          {t.vendor ? `${t.vendor}:${t.product}` : <span title="Recherche par mot-clé">{t.ecosystem ? '' : `mot-clé : ${t.product}`}</span>}
          {t.ecosystem && <div>{t.ecosystem}/{t.packageName}</div>}
        </td>
        <td className="num">{t.vulnerabilityCount}</td>
        <td>{t.openAlertCount > 0 ? <>{t.openAlertCount} <SeverityBadge value={t.maxSeverity} /></> : '0'}</td>
        <td>{t.lastScannedAt ? fmtDateTime(t.lastScannedAt) : <span className="muted">jamais (inventaire au prochain scan)</span>}</td>
        <td className="row-actions">
          <button className="btn btn-small" onClick={() => edit(t)}>Modifier</button>
          <button className="btn btn-small" disabled={busy} onClick={() => run(() => api.rescanTechnology(t.id), `Inventaire complet de « ${t.name} » demandé.`)}>Rescanner</button>
          <button className="btn btn-small btn-danger" disabled={busy} onClick={() => {
            const shared = t.solutions.length > 1 ? `\nElle est utilisée par : ${t.solutions.join(', ')}.` : ''
            if (window.confirm(`Supprimer « ${t.name} » et ses alertes ?${shared}`)) run(() => api.deleteTechnology(t.id), 'Technologie supprimée.')
          }}>Supprimer</button>
        </td>
      </tr>
    )
  }

  const f = (k) => (e) => setForm({ ...form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Ma stack</h1>
          <p className="muted">Technologies surveillées. Changer une version relance la corrélation et ferme les alertes qui ne s'appliquent plus.</p>
        </div>
        <div className="actions">
          <a className="btn" href={api.technologyExportUrl()} title="Télécharger la stack au format config/stack.txt (réimportable)">Exporter</a>
          <button className="btn" onClick={() => setAzdo(!azdo)}>Depuis Azure DevOps</button>
          <button className="btn" onClick={() => { setPreview(null); setImportText(importText || IMPORT_EXAMPLE) }}>Importer une liste</button>
          <button className="btn btn-primary" onClick={() => setForm({ ...EMPTY })}>Ajouter</button>
        </div>
      </header>
      {msg && <div className="info">{msg}</div>}

      {azdo && <AzureDevOpsImport onClose={() => setAzdo(false)} onResult={(text) => { setPreview(null); setImportText(text) }} />}

      {importText !== '' && (
        <section className="card">
          <div className="card-head">
            <h2>Importer (même format que config/stack.txt)</h2>
            <button className="btn btn-ghost" onClick={() => { setImportText(''); setPreview(null) }}>Fermer</button>
          </div>
          <textarea rows={10} className="mono" value={importText} onChange={(e) => setImportText(e.target.value)} />
          <div className="actions">
            <button className="btn" disabled={busy} onClick={async () => {
              try { setPreview(await api.importTechnologies(importText, true)) } catch (e) { setMsg(e.message) }
            }}>Prévisualiser la normalisation</button>
            <button className="btn btn-primary" disabled={busy} onClick={() => run(() => api.importTechnologies(importText, false),
              (r) => `Import : ${r.created} créée(s), ${r.updated} mise(s) à jour, ${r.unchanged} inchangée(s), ${r.lines.filter((l) => l.status === 'error').length} erreur(s).`)}>
              Importer
            </button>
          </div>
          {preview && (
            <table className="table small">
              <thead><tr><th>Ligne</th><th>Solution</th><th>Nom</th><th>Type</th><th>Vendeur:produit (CPE)</th><th>Version</th><th>Écosystème / paquet</th><th>Erreur</th></tr></thead>
              <tbody>
                {preview.lines.map((l) => (
                  <tr key={l.line}>
                    <td>{l.line}</td>
                    <td>{l.normalized?.solutions?.join(', ') || <span className="muted">—</span>}</td>
                    <td>{l.normalized?.name}</td>
                    <td>{TYPE_LABEL[l.normalized?.type] ?? l.normalized?.type}</td>
                    <td className="mono">{l.normalized ? `${l.normalized.vendor || '?'}:${l.normalized.product}` : ''}
                      {l.normalized && !l.normalized.knownProduct && !l.normalized.ecosystem && <div className="muted">produit inconnu : recherche par mot-clé</div>}</td>
                    <td className="mono">{l.normalized?.version || '—'}</td>
                    <td className="mono">{l.normalized?.ecosystem ? `${l.normalized.ecosystem}/${l.normalized.packageName}` : '—'}</td>
                    <td className="error-text">{l.error}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {form && (
        <section className="card">
          <h2>{form.id ? 'Modifier' : 'Ajouter'} une technologie</h2>
          <form className="form-grid" onSubmit={save}>
            <label>Nom *<input required value={form.name} onChange={f('name')} placeholder="ASP.NET Core, PHP, react…" /></label>
            <label>Type
              <select value={form.type} onChange={f('type')}>
                {(meta.data?.types ?? Object.keys(TYPE_LABEL)).map((t) => <option key={t} value={t}>{TYPE_LABEL[t] ?? t}</option>)}
              </select>
            </label>
            <label>Version<input value={form.version} onChange={f('version')} placeholder="8.0.8 (vide = toutes)" /></label>
            <label>Écosystème (paquet)
              <select value={form.ecosystem} onChange={f('ecosystem')}>
                <option value="">— aucun —</option>
                {meta.data?.ecosystems.map((e) => <option key={e} value={e}>{e}</option>)}
              </select>
            </label>
            <label>Nom du paquet<input value={form.packageName} onChange={f('packageName')} placeholder="@angular/core" /></label>
            <label>CPE (facultatif)<input className="mono" value={form.cpe} onChange={f('cpe')} placeholder="cpe:2.3:a:vendeur:produit:*:*:*:*:*:*:*:*" /></label>
            <label>Vendeur CPE<input value={form.vendor} onChange={f('vendor')} placeholder="auto" /></label>
            <label>Produit CPE<input value={form.product} onChange={f('product')} placeholder="auto" /></label>
            <label>Mots-clés<input value={form.keywords} onChange={f('keywords')} /></label>
            <label className="span-2">Solutions
              <input list="solution-names" value={form.solutions} onChange={f('solutions')} placeholder="PAC+, Intranet… (séparées par des virgules)" />
              <datalist id="solution-names">{solutionNames.map((s) => <option key={s} value={s} />)}</datalist>
            </label>
            <label className="span-2">Notes<input value={form.notes} onChange={f('notes')} placeholder="Serveurs concernés, responsable…" /></label>
            <label className="check"><input type="checkbox" checked={form.isActive} onChange={f('isActive')} /> Surveillance active</label>
            <div className="actions span-3">
              <button type="button" className="btn btn-ghost" onClick={() => setForm(null)}>Annuler</button>
              <button type="submit" className="btn btn-primary" disabled={busy}>Enregistrer</button>
            </div>
          </form>
          <p className="muted small">Vendeur/produit sont déduits automatiquement pour les produits courants. Pour un produit inconnu, renseignez la CPE
            (recherche sur <a href="https://nvd.nist.gov/products/cpe/search" target="_blank" rel="noreferrer">nvd.nist.gov/products/cpe</a>).</p>
        </section>
      )}

      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && (
        <>
          <div className="stack-toolbar">
            <label className="check"><input type="checkbox" checked={grouped} onChange={(e) => toggleGrouped(e.target.checked)} /> Regrouper par solution</label>
            {grouped && groups.length > 1 && (
              <span className="muted small">
                {groups.length} groupe(s) ·{' '}
                <button className="btn-link" onClick={() => { setCollapsed([]); store.set('stack.collapsed', []) }}>tout déplier</button>{' · '}
                <button className="btn-link" onClick={() => { const all = groups.map((g) => g.name); setCollapsed(all); store.set('stack.collapsed', all) }}>tout replier</button>
              </span>
            )}
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Technologie</th><th>Type</th><th>Version</th><th>Identification</th><th className="num">Failles</th><th>Alertes ouvertes</th><th>Dernier scan</th><th></th></tr>
              </thead>
              {grouped ? groups.map((g) => {
                const s = groupStats(g.items)
                const isCollapsed = collapsed.includes(g.name)
                return (
                  <tbody key={g.name}>
                    <tr className="group-row" onClick={() => toggleGroup(g.name)} aria-expanded={!isCollapsed}>
                      <th colSpan={8}>
                        <span className="group-caret">{isCollapsed ? '▸' : '▾'}</span>
                        <span className={g.name === NO_SOLUTION ? 'muted' : ''}>{g.name}</span>
                        <span className="group-meta">
                          {g.items.length} technologie(s)
                          {s.open > 0 ? <> · {s.open} alerte(s) ouverte(s) <SeverityBadge value={s.max} /></> : ' · aucune alerte ouverte'}
                          {s.never > 0 && ` · ${s.never} jamais scannée(s)`}
                          {s.inactive > 0 && ` · ${s.inactive} inactive(s)`}
                        </span>
                      </th>
                    </tr>
                    {!isCollapsed && g.items.map((t) => row(t, g.name === NO_SOLUTION ? null : g.name))}
                  </tbody>
                )
              }) : (
                <tbody>{data.map((t) => row(t, null))}</tbody>
              )}
            </table>
          </div>
        </>
      )}
    </>
  )
}
