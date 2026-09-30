/**
 * IPinfo Service
 * Resolves domain IP via DNS-over-HTTPS (DoH) and fetches IP, Country, Organization, and ASN data.
 */

import { ApiError } from '../utils/errorHandler.js';
import { isIpv4Address } from '../utils/urlUtils.js';

const DOH_CLOUDFLARE_URL = 'https://cloudflare-dns.com/dns-query';
const IPINFO_BASE_URL = 'https://ipinfo.io';
const TIMEOUT_MS = 8000;

/**
 * Resolves the A record (IPv4) for a given domain using Cloudflare DNS-over-HTTPS.
 * @param {string} domain 
 * @returns {Promise<string | null>}
 */
export async function resolveDomainIp(domain) {
  if (!domain) return null;
  if (isIpv4Address(domain)) return domain;

  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${DOH_CLOUDFLARE_URL}?name=${encodeURIComponent(domain)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal
    });
    clearTimeout(id);

    if (!response.ok) return null;
    const json = await response.json();

    if (Array.isArray(json.Answer)) {
      // Find first type 1 (A record)
      const aRecord = json.Answer.find(rec => rec.type === 1);
      if (aRecord && isIpv4Address(aRecord.data)) {
        return aRecord.data;
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Fetches IP network intelligence from IPinfo.
 * @param {string} domainOrIp 
 * @param {string} [token] 
 * @returns {Promise<{
 *   configured: boolean,
 *   ip: string | null,
 *   hostname: string | null,
 *   city: string | null,
 *   region: string | null,
 *   country: string | null,
 *   countryCode: string | null,
 *   org: string | null,
 *   asn: string | null,
 *   postal: string | null,
 *   timezone: string | null,
 *   error?: string
 * }>}
 */
export async function getIPInformation(domainOrIp, token = '') {
  if (!domainOrIp) {
    return {
      configured: Boolean(token),
      ip: null,
      hostname: null,
      city: null,
      region: null,
      country: null,
      countryCode: null,
      org: null,
      asn: null,
      postal: null,
      timezone: null,
      error: 'No valid host or IP supplied.'
    };
  }

  // 1. Resolve domain to IPv4 if needed
  let ip = domainOrIp;
  if (!isIpv4Address(domainOrIp)) {
    const resolved = await resolveDomainIp(domainOrIp);
    if (resolved) {
      ip = resolved;
    }
  }

  const hasToken = typeof token === 'string' && token.trim().length > 0;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT_MS);

  // If no token is configured, check if we can query public demo or advise user
  const targetUrl = hasToken
    ? `${IPINFO_BASE_URL}/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token.trim())}`
    : `${IPINFO_BASE_URL}/${encodeURIComponent(ip)}/json`;

  try {
    const response = await fetch(targetUrl, {
      headers: { 'Accept': 'application/json' },
      signal: controller.signal
    });
    clearTimeout(id);

    if (response.status === 401 || response.status === 403) {
      throw new ApiError('Invalid IPinfo token. Check credentials in Settings.', response.status, 'IPinfo');
    }

    if (response.status === 429) {
      throw new ApiError('IPinfo rate limit exceeded (50k requests/mo free tier).', 429, 'IPinfo');
    }

    if (!response.ok) {
      throw new ApiError(`IPinfo API returned HTTP ${response.status}`, response.status, 'IPinfo');
    }

    const data = await response.json();

    // Parse ASN from org string (e.g. "AS15169 Google LLC" -> ASN: "AS15169", Org: "Google LLC")
    let asn = 'N/A';
    let organization = data.org || 'Data unavailable';

    if (data.org && data.org.startsWith('AS')) {
      const parts = data.org.split(' ');
      asn = parts[0];
      organization = parts.slice(1).join(' ') || data.org;
    }

    return {
      configured: hasToken,
      ip: data.ip || ip,
      hostname: data.hostname || 'N/A',
      city: data.city || null,
      region: data.region || null,
      country: data.country ? `${data.country}` : 'Data unavailable',
      countryCode: data.country || null,
      org: organization,
      asn: asn,
      postal: data.postal || null,
      timezone: data.timezone || null,
      error: null
    };
  } catch (err) {
    clearTimeout(id);

    // If request failed because no token was provided and public rate-limited
    if (!hasToken) {
      return {
        configured: false,
        ip: isIpv4Address(ip) ? ip : 'Data unavailable',
        hostname: null,
        city: null,
        region: null,
        country: 'Data unavailable',
        countryCode: null,
        org: 'Data unavailable',
        asn: 'Data unavailable',
        postal: null,
        timezone: null,
        error: 'IPinfo token not configured. Add your token in Settings for full ASN/IP telemetry.'
      };
    }

    return {
      configured: true,
      ip: isIpv4Address(ip) ? ip : null,
      hostname: null,
      city: null,
      region: null,
      country: 'Data unavailable',
      countryCode: null,
      org: 'Data unavailable',
      asn: 'Data unavailable',
      postal: null,
      timezone: null,
      error: err.message || 'Failed to retrieve IP telemetry.'
    };
  }
}
