import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  ArcElement,
  Tooltip,
  Filler,
} from 'chart.js'

ChartJS.register(BarElement, CategoryScale, LinearScale, LineElement, PointElement, ArcElement, Tooltip, Legend, Filler)

export const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
}

export const CHART_PALETTE = ['#c9253a', '#ef7c88', '#7c3445', '#edb4bc', '#94a3b8', '#475569', '#d4a0aa', '#64748b']

export const baseFont = { family: 'Inter, ui-sans-serif, system-ui', size: 11 }

export const commonGridOptions = {
  grid: { color: '#f1f5f9' },
  ticks: { color: '#94a3b8', font: baseFont },
  border: { display: false },
}

/** Validated categorical order (dataviz validator: light mode PASS; contrast WARN -> always show legends/values). */
export const VIZ_CATEGORICAL = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4']
