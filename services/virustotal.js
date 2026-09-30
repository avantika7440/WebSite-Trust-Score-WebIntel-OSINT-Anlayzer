/**
 * VirusTotal API Service (v3)
 * Fetches domain security detections, reputation, and threat indicators.
 */

import { ApiError } from '../utils/errorHandler.js';

const VT_BASE_URL = 'https://www.virustotal.com/api/v3/domains';
const TIMEOUT_MS = 8000;

/**
 * Checks domain reputation on VirusTotal.
 * @param {string} domain 
 * @param {string} apiKey 
 * @returns {Promise<{
 *   configured: boolean,
 *   scanned: boolean,
 *   malicious: number,
 *   suspicious: number,
 *   harmless: number,
 *   undetected: number,
 *   reputation: number,
 *   lastAnalysisDate: string | null,
 *   threatLevel: 'Malicious' | 'Suspicious' | 'Harmless' | 'Unrated',
 *   error?: string
 * }>}
 */
export async function checkDomainReputation(domain, apiKey) {
  if (!apiKey || typeof apiKey !== 'string' || apiKey.trim() === '') {
    return {
      configured: false,
      scanned: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: 0,
      lastAnalysisDate: null,
      threatLevel: 'Unrated',
      error: 'API key not configured. Add your free key in Settings.'
    };
  }

  const cleanDomain = domain.toLowerCase().trim();
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(`${VT_BASE_URL}/${encodeURIComponent(cleanDomain)}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey.trim(),
        'Accept': 'application/json'
      },
      signal: controller.signal
    });
    clearTimeout(id);

    if (response.status === 401 || response.status === 403) {
      throw new ApiError('Invalid VirusTotal API key. Please check your credentials in Settings.', response.status, 'VirusTotal');
    }

    if (response.status === 429) {
      throw new ApiError('VirusTotal rate limit reached (Free tier limit is 4 req/min).', 429, 'VirusTotal');
    }

    if (response.status === 404) {
      return {
        configured: true,
        scanned: false,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: 0,
        lastAnalysisDate: null,
        threatLevel: 'Unrated',
        error: 'Domain not yet indexed or analyzed in VirusTotal database.'
      };
    }

    if (!response.ok) {
      throw new ApiError(`VirusTotal returned HTTP ${response.status}`, response.status, 'VirusTotal');
    }

    const data = await response.json();
    const attributes = data?.data?.attributes || {};
    const stats = attributes.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
    const reputation = attributes.reputation ?? 0;
    const lastAnalysisTimestamp = attributes.last_analysis_date;

    let threatLevel = 'Unrated';
    if (stats.malicious > 0) {
      threatLevel = 'Malicious';
    } else if (stats.suspicious > 0) {
      threatLevel = 'Suspicious';
    } else if (stats.harmless > 0) {
      threatLevel = 'Harmless';
    }

    return {
      configured: true,
      scanned: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      totalEngines: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
      reputation,
      lastAnalysisDate: lastAnalysisTimestamp ? new Date(lastAnalysisTimestamp * 1000).toISOString().split('T')[0] : null,
      threatLevel,
      error: null
    };
  } catch (err) {
    clearTimeout(id);
    return {
      configured: true,
      scanned: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: 0,
      lastAnalysisDate: null,
      threatLevel: 'Unrated',
      error: err.message || 'Failed to query VirusTotal.'
    };
  }
}
