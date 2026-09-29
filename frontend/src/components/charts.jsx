// Graphiques simples (Recharts). Couleurs = palette "statut" réservée à la criticité,
// toujours accompagnées d'une légende + libellés (jamais la couleur seule).
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { SEVERITY_LABEL } from './ui'

export const SEVERITY_COLORS = {
  CRITICAL: '#d03b3b',
  HIGH: '#ec835a',
  MEDIUM: '#fab219',
  LOW: '#0ca30c',
}

const STACK = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] // du bas vers le haut
const axisTick = { fill: 'var(--muted)', fontSize: 12 }

function ChartTooltip({ active, payload, label, labelFormatter }) {
  if (!active || !payload?.length) return null
  const total = payload.reduce((s, p) => s + (p.value ?? 0), 0)
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{labelFormatter ? labelFormatter(label) : label}</div>
      {[...payload].reverse().map((p) => (
        <div key={p.dataKey} className="chart-tooltip-row">
          <span className="swatch" style={{ background: p.color }} />
          <span>{SEVERITY_LABEL[p.dataKey.toUpperCase()] ?? p.name}</span>
          <strong>{p.value}</strong>
        </div>
      ))}
      {payload.length > 1 && <div className="chart-tooltip-row total"><span>Total</span><strong>{total}</strong></div>}
    </div>
  )
}

/** Alertes ouvertes par criticité (une seule série : pas de légende, le titre la nomme). */
export function SeverityBars({ bySeverity }) {
  const data = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => ({
    key: s, name: SEVERITY_LABEL[s], value: bySeverity?.[s] ?? 0, fill: SEVERITY_COLORS[s],
  }))
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 32, top: 4, bottom: 4 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke="var(--grid)" />
        <XAxis type="number" allowDecimals={false} tick={axisTick} axisLine={{ stroke: 'var(--axis)' }} tickLine={false} />
        <YAxis type="category" dataKey="name" tick={{ ...axisTick, fill: 'var(--ink-2)' }} width={80} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: 'var(--hover)' }}
          content={({ active, payload }) => active && payload?.length ? (
            <div className="chart-tooltip">
              <div className="chart-tooltip-row"><span className="swatch" style={{ background: payload[0].payload.fill }} />
                <span>{payload[0].payload.name}</span><strong>{payload[0].value}</strong></div>
            </div>) : null} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} maxBarSize={28} label={{ position: 'right', fill: 'var(--ink-2)', fontSize: 12 }}
          isAnimationActive={false}>
          {data.map((d) => <Cell key={d.key} fill={d.fill} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Nouvelles alertes par jour, empilées par criticité. */
export function TimelineChart({ timeline }) {
  const data = (timeline ?? []).map((d) => ({
    day: d.day, CRITICAL: d.critical, HIGH: d.high, MEDIUM: d.medium, LOW: d.low,
  }))
  const fmt = (d) => new Date(d).toLocaleDateString('fr-CA', { day: 'numeric', month: 'short', timeZone: 'UTC' })
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ left: 0, right: 8, top: 8, bottom: 0 }} barCategoryGap="20%">
        <CartesianGrid vertical={false} stroke="var(--grid)" />
        <XAxis dataKey="day" tickFormatter={fmt} tick={axisTick} axisLine={{ stroke: 'var(--axis)' }} tickLine={false} minTickGap={24} />
        <YAxis allowDecimals={false} tick={axisTick} axisLine={false} tickLine={false} width={32} />
        <Tooltip cursor={{ fill: 'var(--hover)' }} content={<ChartTooltip labelFormatter={fmt} />} />
        <Legend formatter={(v) => <span style={{ color: 'var(--ink-2)' }}>{SEVERITY_LABEL[v]}</span>} iconType="square" />
        {STACK.map((s, i) => (
          <Bar key={s} dataKey={s} stackId="a" fill={SEVERITY_COLORS[s]} stroke="var(--surface)" strokeWidth={1}
            radius={i === STACK.length - 1 ? [4, 4, 0, 0] : 0} isAnimationActive={false} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Technologies les plus exposées (alertes ouvertes empilées par criticité). */
export function TopTechnologiesChart({ items }) {
  const data = (items ?? []).map((t) => ({
    name: `${t.name}${t.version ? ' ' + t.version : ''}`,
    CRITICAL: t.critical, HIGH: t.high, MEDIUM: t.medium, LOW: t.low,
  }))
  if (data.length === 0) return <p className="muted">Aucune alerte ouverte.</p>
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34 + 50)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke="var(--grid)" />
        <XAxis type="number" allowDecimals={false} tick={axisTick} axisLine={{ stroke: 'var(--axis)' }} tickLine={false} />
        <YAxis type="category" dataKey="name" tick={{ ...axisTick, fill: 'var(--ink-2)' }} width={170} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: 'var(--hover)' }} content={<ChartTooltip />} />
        <Legend formatter={(v) => <span style={{ color: 'var(--ink-2)' }}>{SEVERITY_LABEL[v]}</span>} iconType="square" />
        {STACK.map((s, i) => (
          <Bar key={s} dataKey={s} stackId="t" fill={SEVERITY_COLORS[s]} stroke="var(--surface)" strokeWidth={1}
            radius={i === STACK.length - 1 ? [0, 4, 4, 0] : 0} maxBarSize={24} isAnimationActive={false} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}
