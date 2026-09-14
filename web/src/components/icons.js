// WorldC2 — inline SVG icon set (stroke 1.5, no external icon library).
// Each icon is a Vue functional-style component rendered with h().
// All markup is static — no user data ever reaches these paths.

import { h } from 'vue'

function icon(name, shapes, defaultSize = 18) {
  return {
    name: 'Icon' + name,
    props: {
      size: { type: [Number, String], default: defaultSize },
    },
    render() {
      return h(
        'svg',
        {
          xmlns: 'http://www.w3.org/2000/svg',
          viewBox: '0 0 24 24',
          width: this.size,
          height: this.size,
          fill: 'none',
          stroke: 'currentColor',
          'stroke-width': 1.5,
          'stroke-linecap': 'round',
          'stroke-linejoin': 'round',
          'aria-hidden': 'true',
          class: 'icon',
        },
        shapes.map(([tag, attrs]) => h(tag, attrs))
      )
    },
  }
}

const p = (d) => ['path', { d }]
const c = (cx, cy, r) => ['circle', { cx, cy, r }]

/* navigation */

export const IconDashboard = icon('Dashboard', [
  p('M4 4h6.5v6.5H4z'),
  p('M13.5 4H20v6.5h-6.5z'),
  p('M4 13.5h6.5V20H4z'),
  p('M13.5 13.5H20V20h-6.5z'),
])

export const IconSessions = icon('Sessions', [
  p('M3 5h18v11H3z'),
  p('M8.5 20h7'),
  p('M12 16v4'),
  p('M6.5 11.5h2.2l1.4-2.8 2 4.6 1.4-2.3h3.5'),
])

export const IconTerminal = icon('Terminal', [
  p('M4 5h16v14H4z'),
  p('M7.5 9.5l3 2.5-3 2.5'),
  p('M12.5 15h4'),
])

export const IconFiles = icon('Files', [
  p('M3.5 7c0-1.1.9-2 2-2h4.2l2 2.5h6.8c1.1 0 2 .9 2 2v7.5c0 1.1-.9 2-2 2h-13c-1.1 0-2-.9-2-2z'),
])

export const IconModules = icon('Modules', [
  p('M12 3l8 4.5v9L12 21l-8-4.5v-9z'),
  p('M4 7.5l8 4.5 8-4.5'),
  p('M12 12v9'),
])

export const IconOperators = icon('Operators', [
  c(9.5, 7.5, 3.5),
  p('M3 20c.8-3.3 3.4-5.2 6.5-5.2s5.7 1.9 6.5 5.2'),
  p('M15.5 4.4a3.5 3.5 0 010 6.2'),
  p('M17.8 15.2c2 .7 3.4 2.4 3.9 4.8'),
])

export const IconProfiles = icon('Profiles', [
  p('M4 6h16'),
  p('M4 12h16'),
  p('M4 18h16'),
  c(9.5, 6, 2),
  c(15, 12, 2),
  c(7.5, 18, 2),
])

/* actions */

export const IconLogout = icon('Logout', [
  p('M14 4h5a1 1 0 011 1v14a1 1 0 01-1 1h-5'),
  p('M4 12h10.5'),
  p('M11.5 8.5L15 12l-3.5 3.5'),
])

export const IconMenu = icon('Menu', [
  p('M4 7h16'),
  p('M4 12h16'),
  p('M4 17h16'),
])

export const IconClose = icon('Close', [p('M6.5 6.5l11 11'), p('M17.5 6.5l-11 11')])

export const IconSearch = icon('Search', [c(10.5, 10.5, 6.5), p('M15.3 15.3L20 20')])

export const IconDownload = icon('Download', [
  p('M12 4v10.5'),
  p('M8 11l4 3.5 4-3.5'),
  p('M5 19.5h14'),
])

export const IconTrash = icon('Trash', [
  p('M5 7h14'),
  p('M9.5 7V5.5c0-.6.4-1 1-1h3c.6 0 1 .4 1 1V7'),
  p('M7 7l.8 12.1c0 .5.5.9 1 .9h6.4c.5 0 1-.4 1-.9L17 7'),
  p('M10 11v5'),
  p('M14 11v5'),
])

export const IconPlus = icon('Plus', [p('M12 5v14'), p('M5 12h14')])

export const IconRefresh = icon('Refresh', [
  p('M19.5 12a7.5 7.5 0 11-2.2-5.3'),
  p('M17.5 3.5V7H14'),
])

export const IconNote = icon('Note', [
  p('M6 3.5h8.5l3.5 3.5v13.5H6z'),
  p('M14.5 3.5V7H18'),
  p('M9 11h6'),
  p('M9 14.5h6'),
  p('M9 18h3.5'),
])

/* status / misc */

export const IconShield = icon('Shield', [
  p('M12 3l7.5 3v5.5c0 4.6-3.2 7.9-7.5 9.5-4.3-1.6-7.5-4.9-7.5-9.5V6z'),
  p('M9.2 12l2 2 3.6-3.8'),
])

export const IconActivity = icon('Activity', [
  p('M3 12.5h3.5l2.5-6.5 4.5 12 2.5-5.5H21'),
])

export const IconKey = icon('Key', [
  c(8, 14.5, 4),
  p('M11 11.5L20 3'),
  p('M16 4.5L19 7.5'),
  p('M13.5 7l2.5 2.5'),
])
