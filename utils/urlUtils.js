/**
 * URL Utilities for domain extraction, validation, and browser page categorization.
 */

// Common multi-part TLD suffixes
const MULTI_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'me.uk',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.sg', 'edu.sg', 'gov.sg',
  'com.mx', 'edu.mx', 'gob.mx',
  'co.za', 'net.za', 'org.za',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn'
]);

/**
 * Validates if the given URL string is an internal or restricted browser page.
 * @param {string} urlString 
 * @returns {{ isRestricted: boolean, reason?: string }}
 */
export function checkRestrictedUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return { isRestricted: true, reason: 'Empty or invalid URL provided.' };
  }

  const trimmed = urlString.trim().toLowerCase();

  if (trimmed === 'about:blank' || trimmed.startsWith('about:')) {
    return { isRestricted: true, reason: 'Browser system page (about:)' };
  }
  if (trimmed.startsWith('chrome://') || trimmed.startsWith('chrome-extension://')) {
    return { isRestricted: true, reason: 'Chrome internal page' };
  }
  if (trimmed.startsWith('edge://') || trimmed.startsWith('brave://') || trimmed.startsWith('opera://')) {
    return { isRestricted: true, reason: 'Browser internal page' };
  }
  if (trimmed.startsWith('file:///')) {
    return { isRestricted: true, reason: 'Local file system URL (file://)' };
  }
  if (trimmed.startsWith('view-source:')) {
    return { isRestricted: true, reason: 'Source view page' };
  }

  try {
    const parsed = new URL(urlString);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { isRestricted: true, reason: `Unsupported protocol (${parsed.protocol})` };
    }

    const host = parsed.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.local') || host.endsWith('.localhost')) {
      return { isRestricted: true, reason: 'Local development environment (localhost / loopback)' };
    }

    return { isRestricted: false };
  } catch {
    return { isRestricted: true, reason: 'Malformed URL format.' };
  }
}

/**
 * Extracts comprehensive domain parts from a URL string.
 * @param {string} urlString 
 * @returns {object}
 */
export function extractDomainDetails(urlString) {
  try {
    const parsed = new URL(urlString);
    const hostname = parsed.hostname.toLowerCase();
    const protocol = parsed.protocol.replace(':', '');
    const isHttps = parsed.protocol === 'https:';
    const port = parsed.port || (isHttps ? '443' : '80');

    // Extract root domain & TLD
    const parts = hostname.split('.');
    let rootDomain = hostname;
    let tld = '';
    let subdomain = '';

    if (parts.length > 1) {
      const lastTwo = parts.slice(-2).join('.');
      const lastThree = parts.slice(-3).join('.');

      if (parts.length >= 3 && MULTI_PART_TLDS.has(lastTwo)) {
        tld = lastTwo;
        rootDomain = parts.slice(-3).join('.');
        subdomain = parts.slice(0, -3).join('.');
      } else {
        tld = parts[parts.length - 1];
        rootDomain = parts.slice(-2).join('.');
        subdomain = parts.slice(0, -2).join('.');
      }
    }

    return {
      rawUrl: urlString,
      hostname,
      domain: rootDomain,
      subdomain: subdomain || null,
      tld: tld || 'N/A',
      protocol: protocol.toUpperCase(),
      isHttps,
      port,
      pathname: parsed.pathname,
      search: parsed.search
    };
  } catch (err) {
    return {
      rawUrl: urlString,
      hostname: '',
      domain: '',
      subdomain: null,
      tld: 'N/A',
      protocol: 'UNKNOWN',
      isHttps: false,
      port: '',
      pathname: '',
      search: '',
      error: err.message
    };
  }
}

/**
 * Checks if a string is a valid IPv4 address.
 * @param {string} str 
 * @returns {boolean}
 */
export function isIpv4Address(str) {
  if (!str) return false;
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(str.trim());
}
