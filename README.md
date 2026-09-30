# WebIntel OSINT Analyzer — Chrome Extension

**WebIntel OSINT Analyzer** is a modern, lightweight, privacy-conscious Chrome Extension built with **Manifest V3**. It collects publicly available Open Source Intelligence (OSINT) about the website currently open in your active browser tab.

---

## 🚀 Features

* **Target Domain Detection**: Automatically captures the active tab's URL and extracts the domain, hostname, protocol, TLD, and SSL/TLS HTTPS encryption status.
* **Website History (Wayback Machine)**:
  * Retrieves the first recorded historical snapshot date with relative age (e.g., `2001-04-05 (23 yrs ago)`).
  * Retrieves the most recent snapshot date.
  * Provides quick-action buttons to directly view the **Oldest** and **Latest** archived captures on [archive.org](https://archive.org).
  * Works out of the box with zero API key requirement.
* **Security & Threat Intelligence (VirusTotal)**:
  * When configured with a free API key, displays engine scan results (Malicious, Suspicious, Harmless, Undetected).
  * Displays community reputation score and last analysis timestamp.
  * Clear visual badges (Clean, Suspicious, Threat Detected, Unrated).
* **IP & Network Telemetry (IPinfo & DNS-over-HTTPS)**:
  * Resolves target domain IPv4 via Cloudflare DNS-over-HTTPS (DoH).
  * Displays host IP, Country, Organization/ISP, and Autonomous System Number (ASN).
* **In-Popup Settings Drawer**:
  * Easily save or clear optional API keys in `chrome.storage.local`.
  * Zero hardcoded credentials or server dependencies.
* **Edge Case & Error Handling**:
  * Gracefully handles `chrome://`, `about:blank`, `file://`, and `localhost` tabs.
  * Handles rate limits, network outages, un-archived websites, and unindexed domains with clear status messages.

---

## 🛠️ Technologies

* **Core**: HTML5, CSS3, Vanilla JavaScript (ES6+ Modules)
* **Extension Platform**: Chrome Extensions Manifest V3
* **Chrome APIs**: `chrome.tabs`, `chrome.storage.local`
* **Network & REST APIs**:
  * [Internet Archive Wayback Machine CDX & Availability APIs](https://archive.org/help/wayback_api.php)
  * [Cloudflare DNS-over-HTTPS JSON API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
  * [VirusTotal v3 REST API](https://developers.virustotal.com/reference/domain-info) *(Optional)*
  * [IPinfo REST API](https://ipinfo.io/developers) *(Optional)*

---

## 📂 Folder Structure

```text
webintel-osint-analyzer/
│
├── manifest.json                  # Manifest V3 Extension configuration
│
├── popup/
│   ├── popup.html                 # Extension popup markup
│   ├── popup.css                  # Cyber-dark theme & responsive layout
│   └── popup.js                   # Extension popup controller & event dispatcher
│
├── services/
│   ├── wayback.js                 # Wayback Machine CDX & Availability client
│   ├── virustotal.js              # VirusTotal v3 domain reputation client
│   └── ipinfo.js                  # DNS-over-HTTPS resolver & IPinfo client
│
├── utils/
│   ├── urlUtils.js                # URL parsing, TLD extraction, and restriction rules
│   ├── formatUtils.js             # Date, timestamp, and number formatters
│   └── errorHandler.js            # Standardized API error handler & friendly messages
│
├── config/
│   └── config.example.js          # Configuration template & storage keys reference
│
├── assets/
│   └── icons/
│       ├── icon16.png             # 16x16 extension icon
│       ├── icon48.png             # 48x48 extension icon
│       └── icon128.png            # 128x128 extension icon
│
├── README.md                      # Complete project documentation
└── .gitignore                     # Git ignore rules
```

---

## ⚙️ API Configuration

The extension is designed to run immediately without requiring any API keys for basic domain extraction and Wayback Machine history.

To enable optional enhanced threat intelligence and full ASN telemetry:

1. **VirusTotal API Key** *(Optional)*:
   * Sign up for a free account at [virustotal.com](https://www.virustotal.com/gui/join-us).
   * Copy your API key from your profile.
   * Open the extension popup, click the **Gear (⚙)** icon, and paste it into the **VirusTotal API Key** field.
2. **IPinfo Access Token** *(Optional)*:
   * Sign up for a free account at [ipinfo.io/signup](https://ipinfo.io/signup).
   * Copy your access token.
   * Open the extension popup, click the **Gear (⚙)** icon, and paste it into the **IPinfo Token** field.
3. Click **Save Keys**. Keys are stored securely in your browser's `chrome.storage.local`.

---

## 📦 Installation Guide

1. Open **Google Chrome** (or any Chromium-based browser such as Brave, Edge, Opera, or Arc).
2. Navigate to `chrome://extensions` in the address bar.
3. Toggle on **Developer mode** in the top-right corner.
4. Click the **Load unpacked** button in the top-left toolbar.
5. Select this project root directory (`c:\Users\HP\OneDrive\Desktop\Website_Trust_Score Extension`).
6. Pin **WebIntel OSINT Analyzer** to your Chrome toolbar for quick access.
7. Open any website and click the extension icon to begin analysis.

---

## 🧪 Testing Scenarios

| Test Target / Scenario | Expected Behavior |
| :--- | :--- |
| **google.com** | Identifies domain, HTTPS protocol, earliest archive snapshot (~1998), resolved IP, Google LLC ASN. |
| **wikipedia.org** | Displays domain structure, `.org` TLD, oldest archive (~2001), latest archive, and IP telemetry. |
| **github.com** | Identifies GitHub/Microsoft ASN, HTTPS status, clean reputation status, and archive history. |
| **example.com** | Standard domain test verifying RFC-reserved domain handling and IANA archive records. |
| **Brand new / un-archived site** | Displays "No historical snapshots found in the Wayback Machine" with disabled archive buttons. |
| **chrome://extensions** | Displays warning banner: *"OSINT analysis is not available on internal or local browser pages."* |
| **localhost / 127.0.0.1** | Identifies local development environment and displays informative alert. |
| **Missing API keys** | Shows "NO API KEY" badge with guidance to add key in Settings; domain & Wayback remain fully operational. |
| **Network timeout / offline** | Displays user-friendly error note without crashing extension popup. |

---

## 🔒 Security & Privacy Practices

* **Zero Hard-Coded Secrets**: No API keys are stored in the codebase.
* **Minimal Permissions**: Requests only `activeTab` and `storage` permissions.
* **No Browsing Tracking**: The extension inspects URLs only on-demand when clicked.
* **No OSINT Hallucination**: Only verified data from public APIs is displayed; missing fields show `Data unavailable`.

---

## 🔮 Future Roadmap

* [ ] **WHOIS & RDAP Integration**: Domain registrar, creation date, and expiration alerts.
* [ ] **DNS Record Inspector**: A, AAAA, MX, TXT, CNAME, and SPF/DMARC security header analyzer.
* [ ] **Subdomain Reconnaissance**: Discovery via Certificate Transparency (crt.sh).
* [ ] **Technology Stack Profiler**: Detection of web server, CMS, CDN, and frameworks.
* [ ] **Export OSINT Report**: Generate downloadable PDF / JSON investigative summary.
* [ ] **Composite Trust & Risk Score**: Normalized risk rating based on age, SSL status, and threat detections.
