// Theme management: light default, persisted, applied via data-theme on <html>.
const KEY = 'mt_theme'

export function getTheme() {
  return localStorage.getItem(KEY) || 'light'
}

export function applyTheme(t) {
  document.documentElement.dataset.theme = t
  localStorage.setItem(KEY, t)
}

export function initTheme() {
  applyTheme(getTheme())
}

export function toggleTheme() {
  const next = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}
