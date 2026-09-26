<script setup lang="ts">
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import './chartTheme'
import { CHART_PALETTE } from './chartTheme'

const props = withDefaults(
  defineProps<{ data: { label: string; value: number }[]; colors?: string[] }>(),
  {},
)

const palette = computed(() => props.colors ?? CHART_PALETTE)

const chartData = computed(() => ({
  labels: props.data.map((d) => d.label),
  datasets: [{ data: props.data.map((d) => d.value), backgroundColor: palette.value, borderWidth: 2, borderColor: '#fff' }],
}))

const options = {
  responsive: true,
  maintainAspectRatio: false,
  cutout: '68%',
  plugins: { legend: { position: 'right' as const, labels: { boxWidth: 8, boxHeight: 8, usePointStyle: true, font: { size: 11 }, padding: 12 } } },
}
</script>

<template>
  <div class="h-52"><Doughnut :data="chartData" :options="options" /></div>
</template>
