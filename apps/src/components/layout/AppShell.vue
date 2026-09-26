<script setup lang="ts">
import Sidebar from './Sidebar.vue'
import TopBar from './TopBar.vue'
import FirstRunTour from './FirstRunTour.vue'
import ToastContainer from '@/components/common/ToastContainer.vue'
</script>

<template>
  <div class="flex h-screen w-screen overflow-hidden bg-surface-100 text-slate-900">
    <Sidebar />
    <div class="flex min-w-0 flex-1 flex-col">
      <TopBar />
      <main class="flex-1 overflow-y-auto">
        <div class="mx-auto max-w-[1600px] px-4 py-6 md:px-8 md:py-8">
          <slot />
        </div>
      </main>
    </div>
    <ToastContainer />
    <FirstRunTour />
  </div>
</template>
