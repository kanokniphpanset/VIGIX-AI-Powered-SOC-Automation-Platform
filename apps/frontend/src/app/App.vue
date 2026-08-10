<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark"></span>
        <span class="brand-name">SOAR<span class="brand-accent">.</span></span>
      </div>

      <nav class="nav">
        <RouterLink to="/alerts" class="nav-item" active-class="active">
          <span class="nav-label">Alerts</span>
        </RouterLink>
        <RouterLink to="/incidents" class="nav-item" active-class="active">
          <span class="nav-label">Incidents</span>
        </RouterLink>
      </nav>

      <div class="sidebar-footer">
        <span class="status-pill">
          <span class="status-dot"></span>
          Demo SOC
        </span>
      </div>
    </aside>

    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts"></script>

<style scoped>
.shell {
  display: flex;
  height: 100%;
}

.sidebar {
  width: 220px;
  flex-shrink: 0;
  background: var(--bg-surface);
  border-right: 1px solid var(--border-hairline);
  display: flex;
  flex-direction: column;
  padding: var(--space-5) 0;
}

.brand {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: 0 var(--space-5);
  margin-bottom: var(--space-6);
}

.brand-mark {
  width: 8px;
  height: 20px;
  background: var(--accent);
  border-radius: 2px;
}

.brand-name {
  font-family: var(--font-display);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 0.02em;
}

.brand-accent {
  color: var(--accent);
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 0 var(--space-3);
  flex: 1;
}

.nav-item {
  display: block;
  padding: var(--space-3) var(--space-3);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 13px;
  font-weight: 500;
}

.nav-item:hover {
  background: var(--bg-surface-raised);
  color: var(--text-primary);
}

.nav-item.active {
  background: var(--bg-surface-raised);
  color: var(--accent);
}

.sidebar-footer {
  padding: 0 var(--space-5);
}

.status-pill {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  font-size: 12px;
  color: var(--text-muted);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--status-success);
}

.content {
  flex: 1;
  overflow-y: auto;
}
</style>
