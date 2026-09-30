/**
 * WebIntel OSINT Analyzer - Configuration Template
 * 
 * IMPORTANT: API keys should NEVER be hard-coded in extension source code.
 * Instead, configure them dynamically via the Extension Popup Settings drawer,
 * which stores them securely in chrome.storage.local on the user's browser.
 */

export const DEFAULT_CONFIG = {
  // VirusTotal API Key (Free tier allows 4 requests/minute, 500 requests/day)
  // Sign up at: https://www.virustotal.com/gui/join-us
  virustotalApiKey: "983d9b0412a276d509a9585569cb92d24343be79fb167c1d2d9415e3680194a4",

  // IPinfo Access Token (Free tier allows 50,000 requests/month)
  // Sign up at: https://ipinfo.io/signup
  ipinfoToken: "b9f3a1ab33ee84",

  // Timeout thresholds for external requests in milliseconds
  requestTimeoutMs: 10000,

  // Internet Archive endpoints
  waybackCdxUrl: "https://web.archive.org/cdx/search/cdx",
  waybackAvailableUrl: "https://archive.org/wayback/available",

  // Cloudflare DNS-over-HTTPS endpoint for resolving A records
  dnsOverHttpsUrl: "https://cloudflare-dns.com/dns-query"
};

export const STORAGE_KEYS = {
  VIRUSTOTAL_KEY: "webintel_vt_api_key",
  IPINFO_TOKEN: "webintel_ipinfo_token"
};
