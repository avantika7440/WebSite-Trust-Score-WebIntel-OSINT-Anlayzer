/**
 * WebIntel OSINT Analyzer - Main Popup Controller
 * Coordinates tab detection, storage, UI rendering, and API queries.
 */

import { checkRestrictedUrl, extractDomainDetails } from '../utils/urlUtils.js';
import { formatWaybackDate, formatRelativeAge, formatNumber } from '../utils/formatUtils.js';
import { getWaybackData } from '../services/wayback.js';
import { checkDomainReputation } from '../services/virustotal.js';
import { getIPInformation } from '../services/ipinfo.js';

const STORAGE_KEYS = {
  VT_KEY: 'webintel_vt_api_key',
  IPINFO_TOKEN: 'webintel_ipinfo_token'
};

// UI Elements
const els = {
  btnRefresh: document.getElementById('btnRefresh'),
  btnToggleSettings: document.getElementById('btnToggleSettings'),
  settingsDrawer: document.getElementById('settingsDrawer'),
  vtApiKeyInput: document.getElementById('vtApiKey'),
  ipinfoTokenInput: document.getElementById('ipinfoToken'),
  btnSaveSettings: document.getElementById('btnSaveSettings'),
  btnClearSettings: document.getElementById('btnClearSettings'),
  settingsFeedback: document.getElementById('settingsFeedback'),

  targetDomain: document.getElementById('targetDomain'),
  targetHttpsBadge: document.getElementById('targetHttpsBadge'),
  restrictedBanner: document.getElementById('restrictedBanner'),
  restrictedReason: document.getElementById('restrictedReason'),
  intelSections: document.getElementById('intelSections'),

  // Domain Info
  valDomain: document.getElementById('valDomain'),
  valHostname: document.getElementById('valHostname'),
  valProtocol: document.getElementById('valProtocol'),
  valTld: document.getElementById('valTld'),
  valHttps: document.getElementById('valHttps'),

  // Wayback
  valFirstArchive: document.getElementById('valFirstArchive'),
  valLatestArchive: document.getElementById('valLatestArchive'),
  btnViewOldest: document.getElementById('btnViewOldest'),
  btnViewLatest: document.getElementById('btnViewLatest'),
  waybackMsg: document.getElementById('waybackMsg'),

  // VirusTotal
  vtBadge: document.getElementById('vtBadge'),
  statMalicious: document.getElementById('statMalicious'),
  statSuspicious: document.getElementById('statSuspicious'),
  statHarmless: document.getElementById('statHarmless'),
  statUndetected: document.getElementById('statUndetected'),
  valVtReputation: document.getElementById('valVtReputation'),
  valVtDate: document.getElementById('valVtDate'),
  vtMsg: document.getElementById('vtMsg'),

  // IPinfo
  valIp: document.getElementById('valIp'),
  valCountry: document.getElementById('valCountry'),
  valOrg: document.getElementById('valOrg'),
  valAsn: document.getElementById('valAsn'),
  ipinfoMsg: document.getElementById('ipinfoMsg')
};

let currentTabInfo = null;
let currentWaybackUrls = { oldest: null, latest: null };

/**
 * Initializes the popup controller.
 */
async function init() {
  bindEventListeners();
  await loadSavedSettings();
  await analyzeActiveTab();
}

/**
 * Binds UI action handlers.
 */
function bindEventListeners() {
  els.btnRefresh.addEventListener('click', () => {
    analyzeActiveTab();
  });

  els.btnToggleSettings.addEventListener('click', () => {
    els.settingsDrawer.classList.toggle('hidden');
  });

  els.btnSaveSettings.addEventListener('click', saveSettings);
  els.btnClearSettings.addEventListener('click', clearSettings);

  els.btnViewOldest.addEventListener('click', () => {
    if (currentWaybackUrls.oldest) {
      chrome.tabs.create({ url: currentWaybackUrls.oldest });
    }
  });

  els.btnViewLatest.addEventListener('click', () => {
    if (currentWaybackUrls.latest) {
      chrome.tabs.create({ url: currentWaybackUrls.latest });
    }
  });
}

/**
 * Loads API credentials from chrome.storage.local into inputs.
 */
async function loadSavedSettings() {
  try {
    const data = await chrome.storage.local.get([STORAGE_KEYS.VT_KEY, STORAGE_KEYS.IPINFO_TOKEN]);
    if (data[STORAGE_KEYS.VT_KEY]) {
      els.vtApiKeyInput.value = data[STORAGE_KEYS.VT_KEY];
    }
    if (data[STORAGE_KEYS.IPINFO_TOKEN]) {
      els.ipinfoTokenInput.value = data[STORAGE_KEYS.IPINFO_TOKEN];
    }
  } catch (err) {
    console.warn('Could not load stored keys:', err);
  }
}

/**
 * Saves API credentials to chrome.storage.local.
 */
async function saveSettings() {
  const vtKey = els.vtApiKeyInput.value.trim();
  const ipToken = els.ipinfoTokenInput.value.trim();

  try {
    await chrome.storage.local.set({
      [STORAGE_KEYS.VT_KEY]: vtKey,
      [STORAGE_KEYS.IPINFO_TOKEN]: ipToken
    });

    showFeedback('Settings saved successfully. Refreshing analysis...');
    setTimeout(() => {
      els.settingsDrawer.classList.add('hidden');
      analyzeActiveTab();
    }, 900);
  } catch (err) {
    showFeedback('Failed to save settings: ' + err.message, true);
  }
}

/**
 * Clears saved API credentials.
 */
async function clearSettings() {
  els.vtApiKeyInput.value = '';
  els.ipinfoTokenInput.value = '';

  try {
    await chrome.storage.local.remove([STORAGE_KEYS.VT_KEY, STORAGE_KEYS.IPINFO_TOKEN]);
    showFeedback('API keys cleared.');
    setTimeout(() => {
      analyzeActiveTab();
    }, 800);
  } catch (err) {
    showFeedback('Failed to clear settings: ' + err.message, true);
  }
}

/**
 * Displays temporary feedback text in the settings drawer.
 */
function showFeedback(text, isError = false) {
  els.settingsFeedback.textContent = text;
  els.settingsFeedback.classList.remove('hidden');
  els.settingsFeedback.style.color = isError ? 'var(--color-danger)' : 'var(--color-safe)';
  els.settingsFeedback.style.borderColor = isError ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)';
  setTimeout(() => {
    els.settingsFeedback.classList.add('hidden');
  }, 2500);
}

/**
 * Inspects the current active tab and triggers intelligence gathering.
 */
async function analyzeActiveTab() {
  resetUiState();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
      showRestrictedPage('No active tab detected or URL unavailable.');
      return;
    }

    const restrictedCheck = checkRestrictedUrl(tab.url);
    if (restrictedCheck.isRestricted) {
      showRestrictedPage(restrictedCheck.reason);
      return;
    }

    const domainDetails = extractDomainDetails(tab.url);
    currentTabInfo = domainDetails;

    // Render domain basics immediately
    renderDomainInfo(domainDetails);

    // Fetch API keys from storage
    const storageData = await chrome.storage.local.get([STORAGE_KEYS.VT_KEY, STORAGE_KEYS.IPINFO_TOKEN]);
    const vtKey = storageData[STORAGE_KEYS.VT_KEY] || '';
    const ipToken = storageData[STORAGE_KEYS.IPINFO_TOKEN] || '';

    // Asynchronously gather intelligence in parallel
    fetchWaybackIntel(domainDetails.domain || domainDetails.hostname);
    fetchSecurityIntel(domainDetails.domain || domainDetails.hostname, vtKey);
    fetchIpIntel(domainDetails.domain || domainDetails.hostname, ipToken);

  } catch (err) {
    showRestrictedPage('Error analyzing active tab: ' + err.message);
  }
}

/**
 * Resets the UI components to loading state.
 */
function resetUiState() {
  els.restrictedBanner.classList.add('hidden');
  els.intelSections.classList.remove('hidden');

  els.targetDomain.textContent = 'Analyzing...';
  els.targetHttpsBadge.className = 'badge badge-neutral';
  els.targetHttpsBadge.textContent = '...';

  // Domain
  els.valDomain.textContent = '...';
  els.valHostname.textContent = '...';
  els.valProtocol.textContent = '...';
  els.valTld.textContent = '...';
  els.valHttps.textContent = '...';

  // Wayback
  els.valFirstArchive.textContent = 'Scanning archives...';
  els.valLatestArchive.textContent = 'Scanning archives...';
  els.btnViewOldest.disabled = true;
  els.btnViewLatest.disabled = true;
  els.waybackMsg.classList.add('hidden');
  currentWaybackUrls = { oldest: null, latest: null };

  // Security
  els.vtBadge.className = 'badge badge-neutral';
  els.vtBadge.textContent = 'Checking...';
  els.statMalicious.textContent = '-';
  els.statSuspicious.textContent = '-';
  els.statHarmless.textContent = '-';
  els.statUndetected.textContent = '-';
  els.valVtReputation.textContent = '--';
  els.valVtDate.textContent = '--';
  els.vtMsg.classList.add('hidden');

  // IPinfo
  els.valIp.textContent = 'Resolving IP...';
  els.valCountry.textContent = '--';
  els.valOrg.textContent = '--';
  els.valAsn.textContent = '--';
  els.ipinfoMsg.classList.add('hidden');
}

/**
 * Handles restricted or unsupported browser tabs.
 */
function showRestrictedPage(reason = 'Internal browser page') {
  els.restrictedBanner.classList.remove('hidden');
  els.restrictedReason.textContent = reason;
  els.intelSections.classList.add('hidden');
  els.targetDomain.textContent = 'Unsupported URL';
  els.targetHttpsBadge.className = 'badge badge-neutral';
  els.targetHttpsBadge.textContent = 'N/A';
}

/**
 * Renders domain and protocol details.
 */
function renderDomainInfo(details) {
  els.targetDomain.textContent = details.domain || details.hostname;
  
  if (details.isHttps) {
    els.targetHttpsBadge.className = 'badge badge-safe';
    els.targetHttpsBadge.textContent = 'HTTPS';
  } else {
    els.targetHttpsBadge.className = 'badge badge-warning';
    els.targetHttpsBadge.textContent = 'HTTP (INSECURE)';
  }

  els.valDomain.textContent = details.domain || 'N/A';
  els.valHostname.textContent = details.hostname || 'N/A';
  els.valProtocol.textContent = details.protocol;
  els.valTld.textContent = details.tld ? `.${details.tld}` : 'N/A';
  els.valHttps.textContent = details.isHttps ? 'Yes (Secure SSL/TLS)' : 'No (Unencrypted)';
}

/**
 * Fetches and displays Wayback Machine history.
 */
async function fetchWaybackIntel(domain) {
  try {
    const data = await getWaybackData(domain);

    // Save direct links
    if (data.firstArchive?.url) {
      currentWaybackUrls.oldest = data.firstArchive.url;
      els.btnViewOldest.disabled = false;
    }
    if (data.latestArchive?.url) {
      currentWaybackUrls.latest = data.latestArchive.url;
      els.btnViewLatest.disabled = false;
    }

    // Render First Archive date
    if (data.firstArchive?.timestamp) {
      const formattedDate = formatWaybackDate(data.firstArchive.timestamp);
      const relativeAge = formatRelativeAge(data.firstArchive.timestamp);
      els.valFirstArchive.textContent = `${formattedDate} ${relativeAge}`.trim();
    } else if (data.isOffline) {
      els.valFirstArchive.textContent = 'API Maintenance';
    } else if (data.isRateLimited) {
      els.valFirstArchive.textContent = 'Rate Limited';
    } else {
      els.valFirstArchive.textContent = 'No archives found';
    }

    // Render Latest Archive date
    if (data.latestArchive?.timestamp) {
      const formattedDate = formatWaybackDate(data.latestArchive.timestamp);
      const relativeAge = formatRelativeAge(data.latestArchive.timestamp);
      els.valLatestArchive.textContent = `${formattedDate} ${relativeAge}`.trim();
    } else if (data.isOffline) {
      els.valLatestArchive.textContent = 'API Maintenance';
    } else if (data.isRateLimited) {
      els.valLatestArchive.textContent = 'Rate Limited';
    } else {
      els.valLatestArchive.textContent = 'No archives found';
    }

    // Display status or error note
    if (data.error) {
      els.waybackMsg.textContent = data.error;
      els.waybackMsg.classList.remove('hidden');
    }

  } catch (err) {
    els.valFirstArchive.textContent = 'Data unavailable';
    els.valLatestArchive.textContent = 'Data unavailable';
    els.waybackMsg.textContent = 'Wayback Machine query failed: ' + err.message;
    els.waybackMsg.classList.remove('hidden');
  }
}

/**
 * Fetches and displays VirusTotal security reputation.
 */
async function fetchSecurityIntel(domain, apiKey) {
  try {
    const data = await checkDomainReputation(domain, apiKey);

    if (!data.configured) {
      els.vtBadge.className = 'badge badge-neutral';
      els.vtBadge.textContent = 'NO API KEY';
      els.statMalicious.textContent = '0';
      els.statSuspicious.textContent = '0';
      els.statHarmless.textContent = '0';
      els.statUndetected.textContent = '0';
      els.valVtReputation.textContent = 'Data unavailable';
      els.valVtDate.textContent = 'Data unavailable';
      els.vtMsg.textContent = 'VirusTotal API key not configured. Add your key in Settings for live malware & phishing telemetry.';
      els.vtMsg.classList.remove('hidden');
      return;
    }

    if (data.error && !data.scanned) {
      els.vtBadge.className = 'badge badge-neutral';
      els.vtBadge.textContent = 'UNRATED';
      els.statMalicious.textContent = '-';
      els.statSuspicious.textContent = '-';
      els.statHarmless.textContent = '-';
      els.statUndetected.textContent = '-';
      els.valVtReputation.textContent = 'Data unavailable';
      els.valVtDate.textContent = 'Data unavailable';
      els.vtMsg.textContent = data.error;
      els.vtMsg.classList.remove('hidden');
      return;
    }

    // Render Stats
    els.statMalicious.textContent = formatNumber(data.malicious);
    els.statSuspicious.textContent = formatNumber(data.suspicious);
    els.statHarmless.textContent = formatNumber(data.harmless);
    els.statUndetected.textContent = formatNumber(data.undetected);

    els.valVtReputation.textContent = `${data.reputation > 0 ? '+' : ''}${data.reputation}`;
    els.valVtDate.textContent = data.lastAnalysisDate || 'Recent';

    // Threat level badge
    if (data.threatLevel === 'Malicious') {
      els.vtBadge.className = 'badge badge-danger';
      els.vtBadge.textContent = `${data.malicious} THREATS DETECTED`;
    } else if (data.threatLevel === 'Suspicious') {
      els.vtBadge.className = 'badge badge-warning';
      els.vtBadge.textContent = `${data.suspicious} SUSPICIOUS`;
    } else if (data.threatLevel === 'Harmless') {
      els.vtBadge.className = 'badge badge-safe';
      els.vtBadge.textContent = 'CLEAN / REPUTABLE';
    } else {
      els.vtBadge.className = 'badge badge-neutral';
      els.vtBadge.textContent = 'UNRATED';
    }

  } catch (err) {
    els.vtBadge.className = 'badge badge-neutral';
    els.vtBadge.textContent = 'ERROR';
    els.vtMsg.textContent = 'Security check failed: ' + err.message;
    els.vtMsg.classList.remove('hidden');
  }
}

/**
 * Fetches and displays IP & Network telemetry from IPinfo.
 */
async function fetchIpIntel(domain, ipToken) {
  try {
    const data = await getIPInformation(domain, ipToken);

    els.valIp.textContent = data.ip || 'Data unavailable';
    els.valCountry.textContent = data.country || 'Data unavailable';
    els.valOrg.textContent = data.org || 'Data unavailable';
    els.valOrg.title = data.org || '';
    els.valAsn.textContent = data.asn || 'Data unavailable';

    if (data.error) {
      els.ipinfoMsg.textContent = data.error;
      els.ipinfoMsg.classList.remove('hidden');
    }
  } catch (err) {
    els.valIp.textContent = 'Data unavailable';
    els.valCountry.textContent = 'Data unavailable';
    els.valOrg.textContent = 'Data unavailable';
    els.valAsn.textContent = 'Data unavailable';
    els.ipinfoMsg.textContent = 'IP lookup failed: ' + err.message;
    els.ipinfoMsg.classList.remove('hidden');
  }
}

// Start on DOM ready
document.addEventListener('DOMContentLoaded', init);
