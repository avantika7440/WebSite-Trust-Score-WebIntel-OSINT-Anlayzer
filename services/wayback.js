/**
 * Wayback Machine Service
 * Fetches historical website snapshots from the Internet Archive (web.archive.org).
 * Handles live CDX responses, maintenance outages, rate limits, and fallback redirect URLs.
 */

import { ApiError } from '../utils/errorHandler.js';

const CDX_API_URL = 'https://web.archive.org/cdx/search/cdx';
const TIMEOUT_MS = 10000;

/**
 * Safely fetches and inspects response for valid JSON or Internet Archive maintenance pages.
 * @param {string} url 
 * @param {number} timeoutMs 
 * @returns {Promise<{ isJson: boolean, data?: any, isOffline?: boolean, isRateLimited?: boolean, status: number }>}
 */
async function fetchWaybackEndpoint(url, timeoutMs = TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json, text/plain, */*'
      }
    });
    clearTimeout(id);

    const status = response.status;

    if (status === 429) {
      return { isJson: false, isRateLimited: true, status };
    }

    const text = await response.text();
    const trimmed = text.trim();

    // Detect Internet Archive maintenance / offline landing page
    if (trimmed.includes('Temporarily Offline') || trimmed.includes('Internet Archive services are temporarily offline') || status === 503) {
      return { isJson: false, isOffline: true, status };
    }

    try {
      const json = JSON.parse(trimmed);
      return { isJson: true, data: json, status };
    } catch {
      return { isJson: false, isOffline: status >= 500, status };
    }
  } catch (err) {
    clearTimeout(id);
    if (err.name === 'AbortError') {
      return { isJson: false, isOffline: true, status: 408 };
    }
    return { isJson: false, isOffline: false, status: 0 };
  }
}

/**
 * Parses snapshot row from CDX response format [['timestamp', 'original', 'statuscode'], ['20211129...', 'http://...']]
 * @param {Array} cdxData 
 * @param {string} fallbackTarget 
 * @returns {{ timestamp: string, original: string, url: string } | null}
 */
function parseCdxRow(cdxData, fallbackTarget) {
  if (!Array.isArray(cdxData) || cdxData.length < 2) return null;
  const row = cdxData[1];
  if (!row || !row[0]) return null;

  const timestamp = String(row[0]).trim();
  const original = row[1] || fallbackTarget;
  const url = original.startsWith('http')
    ? `https://web.archive.org/web/${timestamp}/${original}`
    : `https://web.archive.org/web/${timestamp}/https://${original}`;

  return {
    timestamp,
    original,
    url
  };
}

/**
 * Retrieves the oldest and latest snapshot data for a given domain or URL.
 * @param {string} domainOrHostname 
 * @returns {Promise<{
 *   hasArchives: boolean,
 *   isOffline?: boolean,
 *   isRateLimited?: boolean,
 *   firstArchive: { timestamp: string, url: string, date?: string } | null,
 *   latestArchive: { timestamp: string, url: string, date?: string } | null,
 *   error?: string
 * }>}
 */
export async function getWaybackData(domainOrHostname) {
  if (!domainOrHostname) {
    return {
      hasArchives: false,
      firstArchive: null,
      latestArchive: null,
      error: 'No valid domain provided.'
    };
  }

  const cleanTarget = domainOrHostname.toLowerCase().trim();

  // Direct Wayback redirect URLs that work directly in browser even during partial API outages
  const directOldestUrl = `https://web.archive.org/web/19960101000000/https://${cleanTarget}`;
  const directLatestUrl = `https://web.archive.org/web/2/https://${cleanTarget}`;

  try {
    const oldestUrl = `${CDX_API_URL}?url=${encodeURIComponent(cleanTarget)}&output=json&fl=timestamp,original,statuscode&limit=1`;
    const latestUrl = `${CDX_API_URL}?url=${encodeURIComponent(cleanTarget)}&output=json&fl=timestamp,original,statuscode&sort=reverse&limit=1`;

    const [oldestRes, latestRes] = await Promise.all([
      fetchWaybackEndpoint(oldestUrl),
      fetchWaybackEndpoint(latestUrl)
    ]);

    // Check for maintenance or rate limit states
    if (oldestRes.isOffline || latestRes.isOffline) {
      return {
        hasArchives: true, // Allow user to view via direct URL
        isOffline: true,
        firstArchive: { timestamp: '', original: cleanTarget, url: directOldestUrl },
        latestArchive: { timestamp: '', original: cleanTarget, url: directLatestUrl },
        error: 'Internet Archive servers are currently experiencing high load or temporary maintenance. Direct view links remain active.'
      };
    }

    if (oldestRes.isRateLimited || latestRes.isRateLimited) {
      return {
        hasArchives: true,
        isRateLimited: true,
        firstArchive: { timestamp: '', original: cleanTarget, url: directOldestUrl },
        latestArchive: { timestamp: '', original: cleanTarget, url: directLatestUrl },
        error: 'Wayback Machine rate limit reached. Click buttons below to view archives directly.'
      };
    }

    let firstSnapshot = oldestRes.isJson ? parseCdxRow(oldestRes.data, cleanTarget) : null;
    let latestSnapshot = latestRes.isJson ? parseCdxRow(latestRes.data, cleanTarget) : null;

    // If both snapshots are found, ensure oldest is not newer than latest
    if (firstSnapshot && latestSnapshot && firstSnapshot.timestamp > latestSnapshot.timestamp) {
      const temp = firstSnapshot;
      firstSnapshot = latestSnapshot;
      latestSnapshot = temp;
    }

    if (firstSnapshot && !latestSnapshot) {
      latestSnapshot = firstSnapshot;
    } else if (!firstSnapshot && latestSnapshot) {
      firstSnapshot = latestSnapshot;
    }

    const hasArchives = Boolean(firstSnapshot || latestSnapshot);

    return {
      hasArchives,
      isOffline: false,
      firstArchive: firstSnapshot || { timestamp: '', original: cleanTarget, url: directOldestUrl },
      latestArchive: latestSnapshot || { timestamp: '', original: cleanTarget, url: directLatestUrl },
      error: hasArchives ? null : 'No historical snapshots found for this domain in the Wayback Machine.'
    };
  } catch (err) {
    return {
      hasArchives: true,
      isOffline: true,
      firstArchive: { timestamp: '', original: cleanTarget, url: directOldestUrl },
      latestArchive: { timestamp: '', original: cleanTarget, url: directLatestUrl },
      error: 'Unable to reach Wayback Machine API: ' + (err.message || 'Network error')
    };
  }
}
