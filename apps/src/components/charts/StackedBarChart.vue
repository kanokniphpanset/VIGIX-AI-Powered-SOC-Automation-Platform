<script setup lang="ts">
import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import { baseFont, commonGridOptions } from './chartTheme'

/** Stacked bars over categories (e.g. days) — one dataset per series; legend + hover tooltip always on. */
const props = defineProps<{ labels: string[]; series: { label: string; color: string; data: number[] }[]; height?: number }>()

const chartData = computed(() => ({
  labels: props.labels,
  datasets: props.series.map((s) => ({
    label: s.label,
    data: s.data,
    backgroundColor: s.color,
    borderColor: '#ffffff',
    borderWidth: { top: 2, right: 0, bottom: 0, left: 0 },
    borderRadius: 4,
    borderSkipped: false as const,
    maxBarThickness: 26,
    stack: 'total',
  })),
}))

const options = {
  responsive: true,
  maintainAspectRatio: false,
  interaction: { mode: 'index' as const, intersect: false },
  plugins: {
    legend: { position: 'bottom' as const, labels: { boxWidth: 10, boxHeight: 10, useBorderRadius: true, borderRadius: 2, color: '#475569', font: baseFont } },
    tooltip: { backgroundColor: '#0f172a', titleFont: baseFont, bodyFont: baseFont, padding: 10, boxPadding: 4 },
  },
  scales: {
    x: { ...commonGridOptions, stacked: true, grid: { display: false } },
    y: { ...commonGridOptions, stacked: true, beginAtZero: true, ticks: { ...commonGridOptions.ticks, precision: 0 } },
  },
}
</script>

<template>
  <div :style="{ height: `${height ?? 260}px` }">
    <Bar :data="chartData" :options="options" />
  </div>
</template>
