import { useState } from 'react'
import { api, useApi } from '../api'
import { ErrorBox, Loading } from './ui'

/**
 * Choix des dépôts Azure DevOps à lire et de la solution de chacun (plusieurs dépôts peuvent partager une solution).
 * Le résultat est un texte au format stack.txt, remis à `onResult` pour passer par l'aperçu et l'import habituels.
 */
export default function AzureDevOpsImport({ onResult, onClose }) {
  const { data: repos, error, loading } = useApi(() => api.azdoRepositories(), [])
  const [rows, setRows] = useState({}) // clé "projet/dépôt" -> { checked, solution, branch }
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [err, setErr] = useState(null)

  const key = (r) => `${r.project}/${r.name}`
  const get = (r) => rows[key(r)] ?? { checked: false, solution: r.suggestedSolution, branch: '' }
  const set = (r, patch) => setRows({ ...rows, [key(r)]: { ...get(r), ...patch } })

  const visible = (repos ?? []).filter((r) => key(r).toLowerCase().includes(filter.toLowerCase()))
  const selected = (repos ?? []).filter((r) => get(r).checked)

  const scan = async () => {
    setBusy(true); setErr(null); setResult(null)
    try {
      const res = await api.azdoScan(selected.map((r) => ({
        project: r.project, repo: r.name, solution: get(r).solution, branch: get(r).branch || null, kind: r.kind,
      })))
      setResult(res)
      onResult(res.text)
    } catch (e) { setErr(e.message) }
    finally { setBusy(false) }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Importer depuis Azure DevOps</h2>
        <button className="btn btn-ghost" onClick={onClose}>Fermer</button>
      </div>
      <p className="muted small">
        Lecture seule. Cochez les dépôts et indiquez leur solution (donnez le même nom à plusieurs dépôts pour les regrouper).
        La stack déduite apparaît ensuite dans la zone d'import, à prévisualiser avant d'enregistrer.
      </p>

      {loading && <Loading />}
      {error && <ErrorBox error={error} />}
      {repos && (
        <>
          <input placeholder="Filtrer les dépôts…" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <table className="table small">
            <thead><tr><th></th><th>Projet / dépôt</th><th>Solution</th><th>Branche (vide = {'défaut'})</th></tr></thead>
            <tbody>
              {visible.map((r) => {
                const g = get(r)
                return (
                  <tr key={key(r)}>
                    <td><input type="checkbox" checked={g.checked} onChange={(e) => set(r, { checked: e.target.checked })} /></td>
                    <td>
                      {r.kind === 'tfvc'
                        ? <><strong>{r.name}</strong> <span className="tag">TFVC</span></>
                        : <>{r.project} / <strong>{r.name}</strong> {r.defaultBranch && <span className="muted">({r.defaultBranch})</span>}</>}
                    </td>
                    <td><input value={g.solution} onChange={(e) => set(r, { solution: e.target.value })} /></td>
                    <td>{r.kind === 'tfvc'
                      ? <span className="muted">dernière version</span>
                      : <input value={g.branch} placeholder={r.defaultBranch ?? 'main'} onChange={(e) => set(r, { branch: e.target.value })} />}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          <div className="actions">
            <button className="btn btn-primary" disabled={busy || selected.length === 0} onClick={scan}>
              {busy ? 'Analyse en cours…' : `Analyser ${selected.length} dépôt(s)`}
            </button>
          </div>
        </>
      )}

      {err && <div className="info error-text">{err}</div>}
      {result && (
        <table className="table small">
          <thead><tr><th>Dépôt</th><th>Solution</th><th>Branche</th><th>Fichiers lus</th><th>Technologies</th><th>Remarques</th></tr></thead>
          <tbody>
            {result.repos.map((r) => (
              <tr key={`${r.project}/${r.repo}`}>
                <td>{r.repo.startsWith('$/') ? r.repo : `${r.project} / ${r.repo}`}</td>
                <td>{r.solution}</td>
                <td className="mono">{r.branch ?? '—'}</td>
                <td title={r.files.join('\n')}>{r.files.length}</td>
                <td className="num">{r.technologies}</td>
                <td>
                  {r.error && <div className="error-text">{r.error}</div>}
                  {r.warnings.map((w) => <div key={w} className="muted">{w}</div>)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
