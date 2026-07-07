import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Login from './views/Login.vue'
import Dashboard from './views/Dashboard.vue'
import Sessions from './views/Sessions.vue'
import Files from './views/Files.vue'
import Modules from './views/Modules.vue'
import Operators from './views/Operators.vue'
import Terminal from './views/Terminal.vue'

const routes = [
  { path: '/login', name: 'Login', component: Login, meta: { guest: true } },
  { path: '/', name: 'Dashboard', component: Dashboard, meta: { requiresAuth: true, title: 'Dashboard' } },
  { path: '/sessions', name: 'Sessions', component: Sessions, meta: { requiresAuth: true, title: 'Victims' } },
  { path: '/terminal', name: 'Terminal', component: Terminal, meta: { requiresAuth: true, title: 'Terminal' } },
  { path: '/files', name: 'Files', component: Files, meta: { requiresAuth: true, title: 'Files' } },
  { path: '/modules', name: 'Modules', component: Modules, meta: { requiresAuth: true, title: 'Modules' } },
  { path: '/operators', name: 'Operators', component: Operators, meta: { requiresAuth: true, requiresAdmin: true, title: 'Operators' } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach((to, from, next) => {
  const isAuthenticated = !!sessionStorage.getItem('bty_token')

  // Update page title
  document.title = to.meta.title ? `WORLDC2 C2 - ${to.meta.title}` : 'WORLDC2 C2'

  // Redirect authenticated users away from login
  if (to.meta.guest && isAuthenticated) {
    next('/')
    return
  }

  // Require authentication
  if (to.meta.requiresAuth && !isAuthenticated) {
    next('/login')
    return
  }

  // Require admin role
  if (to.meta.requiresAdmin) {
    const role = sessionStorage.getItem('bty_role')
    if (role !== 'admin') {
      next('/')
      return
    }
  }

  next()
})

// Handle navigation errors
router.onError((err) => {
  console.error('Router error:', err)
})

const app = createApp(App)
app.use(router)
app.mount('#app')

export default router
