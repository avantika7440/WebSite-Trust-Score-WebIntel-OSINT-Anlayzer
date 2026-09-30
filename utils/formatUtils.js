/**
 * Formatting Utilities for timestamps, numbers, and display labels.
 */

/**
 * Converts a Wayback 14-digit timestamp (YYYYMMDDhhmmss) or ISO date into YYYY-MM-DD.
 * @param {string|number} timestamp 
 * @returns {string} Formatted date string or 'N/A'
 */
export function formatWaybackDate(timestamp) {
  if (!timestamp) return 'Data unavailable';
  
  const str = String(timestamp).trim();
  if (str.length >= 8) {
    const year = str.substring(0, 4);
    const month = str.substring(4, 6);
    const day = str.substring(6, 8);
    return `${year}-${month}-${day}`;
  }

  // Attempt standard date parsing
  const dateObj = new Date(timestamp);
  if (!isNaN(dateObj.getTime())) {
    return dateObj.toISOString().split('T')[0];
  }

  return 'Data unavailable';
}

/**
 * Calculates a friendly human-readable age / relative time.
 * @param {string|number} timestamp 
 * @returns {string} e.g. "18 years ago" or ""
 */
export function formatRelativeAge(timestamp) {
  if (!timestamp) return '';
  const str = String(timestamp).trim();
  if (str.length >= 8) {
    const year = parseInt(str.substring(0, 4), 10);
    const currentYear = new Date().getFullYear();
    const diff = currentYear - year;
    if (diff > 1) return `(${diff} yrs ago)`;
    if (diff === 1) return `(1 yr ago)`;
    if (diff === 0) return `(This year)`;
  }
  return '';
}

/**
 * Formats standard number with commas.
 * @param {number} num 
 * @returns {string}
 */
export function formatNumber(num) {
  if (num === undefined || num === null || isNaN(num)) return '0';
  return Number(num).toLocaleString('en-US');
}

/**
 * Sanitizes input string to prevent XSS before rendering into HTML.
 * @param {string} str 
 * @returns {string}
 */
export function sanitizeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
