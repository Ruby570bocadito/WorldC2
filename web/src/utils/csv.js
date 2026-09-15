// csv.js — client-side CSV serialization for the console.
//
// Exports are built in the browser from data already rendered (the vault
// listing), so no extra endpoint or permission surface is needed. The
// serializer applies two guards that a naive join() would miss:
//
// 1. RFC 4180 quoting: cells containing quotes, commas, CR or LF are
//    wrapped in double quotes with inner quotes doubled.
// 2. Formula-injection guard: a cell that a spreadsheet application would
//    evaluate (=cmd, +1, -1, @x, tab-led) is prefixed with a single quote.
//    Captured credentials come from untrusted hosts, so "=HYPERLINK(...)"
//    as a username must land as inert text, not as an executable formula
//    when the operator opens the export in Excel/Sheets.

const FORMULA_PREFIXES = ['=', '+', '-', '@', '\t', '\r']

/**
 * Makes a single cell safe: quotes when needed, neutralizes formula leads.
 * @param {unknown} value
 * @returns {string}
 */
export function csvCell(value) {
  if (value === null || value === undefined) return ''
  let s = String(value)
  if (FORMULA_PREFIXES.some((p) => s.startsWith(p))) {
    s = "'" + s
  }
  if (/[",\r\n]/.test(s)) {
    s = '"' + s.replace(/"/g, '""') + '"'
  }
  return s
}

/**
 * Builds a CSV document from rows of objects.
 * @param {string[]} headers column titles, in order
 * @param {Array<Record<string, unknown>>} rows data rows
 * @param {string[]} fields row keys matching the headers, in order
 * @returns {string}
 */
export function toCSV(headers, rows, fields) {
  const lines = [headers.map(csvCell).join(',')]
  for (const row of rows) {
    lines.push(fields.map((f) => csvCell(row[f])).join(','))
  }
  return lines.join('\r\n') + '\r\n'
}

/**
 * Triggers a browser download of a text document. Revokes the blob URL
 * once the browser has grabbed it so no object URL leaks per export.
 * @param {string} filename
 * @param {string} content
 * @param {string} mime
 */
export function downloadText(filename, content, mime = 'text/csv;charset=utf-8') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  // Give the click handler a tick, then release the object URL.
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
