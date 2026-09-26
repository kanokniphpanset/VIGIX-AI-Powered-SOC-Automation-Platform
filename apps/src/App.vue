<script setup lang="ts">
import { watch } from 'vue'
import { useRoute } from 'vue-router'
import AppShell from '@/components/layout/AppShell.vue'
import { locale } from '@/i18n'
import { applyTitle } from '@/router'

const route = useRoute()
watch(locale, () => applyTitle())
</script>

<template>
  <router-view v-if="route.meta.public" />
  <AppShell v-else>
    <router-view v-slot="{ Component, route }">
      <transition name="fade" mode="out-in">
        <component :is="Component" :key="route.fullPath" />
      </transition>
    </router-view>
  </AppShell>
</template>

<style>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.12s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
