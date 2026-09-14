import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Login from './views/Login.vue'
import Dashboard from './views/Dashboard.vue'
import Sessions from './views/Sessions.vue'
import Files from './views/Files.vue'
import Modules from './views/Modules.vue'
import Profiles from './views/Profiles.vue'
import Operators from './views/Operators.vue'
import Terminal from './views/Terminal.vue'
import './assets/main.css'
import './utils/notifications.js'

const routes = [
  { path: '/login', name: 'Login', component: Login, meta: { guest: true } },
  { path: '/', name: 'Dashboard', component: Dashboard, meta: { requiresAuth: true, title: 'Dashboard' } },
  { path: '/sessions', name: 'Sessions', component: Sessions, meta: { requiresAuth: true, title: 'Sessions' } },
  { path: '/terminal', name: 'Terminal', component: Terminal, meta: { requiresAuth: true, title: 'Command Runner' } },
  { path: '/files', name: 'Files', component: Files, meta: { requiresAuth: true, title: 'Files' } },
  { path: '/modules', name: 'Modules', component: Modules, meta: { requiresAuth: true, title: 'Modules' } },
  { path: '/profiles', name: 'Profiles', component: Profiles, meta: { requiresAuth: true, title: 'Profiles' } },
  { path: '/operators', name: 'Operators', component: Operators, meta: { requiresAuth: true, requiresAdmin: true, title: 'Operators' } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach((to) => {
  const token = localStorage.getItem('bty_token')

  document.title = to.meta.title
    ? 'WorldC2 — ' + to.meta.title
    : 'WorldC2 — Operator Console'

  if (to.meta.guest && token) return '/'

  if (to.meta.requiresAuth && !token) return '/login'

  if (to.meta.requiresAdmin) {
    const role = localStorage.getItem('bty_role')
    if (role !== 'admin') return '/'
  }

  return true
})

const app = createApp(App)
app.use(router)
app.mount('#app')
