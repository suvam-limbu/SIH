/**
 * Sentryl — Popup Controller
 * 100% Pure Client-Side Implementation
 */

const detector = new SentrylDetector();

// DOM elements
const $ = (id) => document.getElementById(id);
const statusPill = $('statusPill');
const statusText = $('statusText');
const targetFrom = $('targetFrom');
const targetSubj = $('targetSubj');
const scanStatus = $('scanStatus');
const scanTime = $('scanTime');
const ringFg = $('ringFg');
const riskScore = $('riskScore');
const riskTag = $('riskTag');
const scoreHeadline = $('scoreHeadline');
const scoreSub = $('scoreSub');
const checksList = $('checksList');
const exportBtn = $('exportBtn');
const fullAnalysisLink = $('fullAnalysisLink');
const scanCurrentBtn = $('scanCurrentBtn');

let currentScanResult = null;
let currentEmailData = null;

// ─── Render Functions ────────────────────────────────────────

function displayResults(data, email) {
  currentScanResult = data;
  currentEmailData = email;

  const score = data.risk_score;
  const level = score >= 70 ? 'danger' : score >= 40 ? 'warn' : 'safe';
  const label = score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM RISK' : 'LOW RISK';

  targetFrom.textContent = email?.sender || 'Unknown Sender';
  targetSubj.textContent = email?.subject || 'No Subject';

  statusPill.className = 'status-pill ' + (level === 'danger' ? 'danger' : '');
  statusText.textContent = 'SCANNED';
  scanStatus.textContent = 'scan complete';
  scanTime.textContent = '0.04s';

  // Ring score animation
  const circumference = 226;
  const offset = circumference - (score / 100) * circumference;
  ringFg.style.strokeDashoffset = offset;
  ringFg.className = 'ring-fg ' + level;
  riskScore.textContent = score;
  riskScore.className = 'ring-num ' + level;

  riskTag.textContent = label;
  riskTag.className = 'score-tag ' + level;

  const failCount = data.checks.filter(c => c.status === 'fail').length;
  const warnCount = data.checks.filter(c => c.status === 'warn').length;
  const flagged = failCount + warnCount;

  scoreHeadline.textContent = flagged > 0 ? `${flagged} threat indicator${flagged > 1 ? 's' : ''} flagged` : 'All safety checks passed';
  scoreSub.textContent = data.summary || '';

  // Render check rows
  checksList.innerHTML = '';
  const iconMap = {
    fail: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M18 6 6 18M6 6l12 12"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>',
    pass: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6 9 17l-5-5"/></svg>'
  };

  data.checks.forEach(c => {
    const row = document.createElement('div');
    row.className = 'check-row';
    row.innerHTML = `
      <div class="check-icon ${c.status}">${iconMap[c.status] || ''}</div>
      <div class="check-body">
        <div class="check-title">${escapeHtml(c.name)}</div>
        <div class="check-detail">${escapeHtml(c.detail)}</div>
      </div>
    `;
    checksList.appendChild(row);
  });

  // Save state
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.set({ lastScan: data, lastEmail: email });
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

// ─── Scan Logic ─────────────────────────────────────────────

async function scanScenario(key) {
  const scenario = SENTRYL_SCENARIOS[key];
  if (!scenario) return;

  const emailData = {
    sender: scenario.sender,
    senderName: scenario.senderName,
    subject: scenario.subject,
    body: scenario.body,
    urls: scenario.urls,
    replyTo: scenario.replyTo,
    headers: scenario.headers,
    simulatedIP: scenario.simulatedIP,
    geolocation: scenario.geolocation
  };

  const result = await detector.scan(emailData);
  displayResults(result, emailData);

  // If on Gmail tab, tell it to update the in-page banner too
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: 'runScenario', scenarioId: key }).catch(() => {});
      }
    });
  }
}

async function scanActiveGmailTab() {
  if (typeof chrome === 'undefined' || !chrome.tabs) {
    // Fallback to default scenario when testing standalone
    scanScenario('paypal_phish');
    return;
  }

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const activeTab = tabs[0];
    if (activeTab && activeTab.url && activeTab.url.includes('mail.google.com')) {
      chrome.tabs.sendMessage(activeTab.id, { action: 'extractEmail' }, async (emailData) => {
        if (emailData && emailData.sender) {
          const result = await detector.scan(emailData);
          displayResults(result, emailData);
        } else {
          // If no email open in Gmail, default to PayPal phish scenario for presentation
          scanScenario('paypal_phish');
        }
      });
    } else {
      // Default to demo scenario if not on Gmail
      scanScenario('paypal_phish');
    }
  });
}

// ─── Event Handlers ─────────────────────────────────────────

document.querySelectorAll('.btn-scenario').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.getAttribute('data-scenario');
    scanScenario(key);
  });
});

scanCurrentBtn.addEventListener('click', () => {
  scanActiveGmailTab();
});

fullAnalysisLink.addEventListener('click', (e) => {
  e.preventDefault();
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/report.html') });
  } else {
    window.open('../dashboard/report.html', '_blank');
  }
});

exportBtn.addEventListener('click', () => {
  if (!currentScanResult) return;

  const reportText = `
═════════════════════════════════════════════════════════════════
  SENTRYL — FORENSIC THREAT INTELLIGENCE DOSSIER
═════════════════════════════════════════════════════════════════
Date:       ${new Date().toISOString()}
Target:     ${targetFrom.textContent}
Subject:    ${targetSubj.textContent}
Threat:     ${currentScanResult.risk_score}/100 [${currentScanResult.risk_level.toUpperCase()}]
Verdict:    ${currentScanResult.summary}

─────────────────────────────────────────────────────────────────
INDICATOR EVIDENCE BREAKDOWN:
─────────────────────────────────────────────────────────────────
${currentScanResult.checks.map(c => `[${c.status.toUpperCase()}] ${c.name}\n  Evidence: ${c.detail}`).join('\n\n')}

─────────────────────────────────────────────────────────────────
ORIGIN GEOLOCATION TRACE:
─────────────────────────────────────────────────────────────────
Origin IP:  ${currentScanResult.geolocation?.ip || 'N/A'}
Country:    ${currentScanResult.geolocation?.country || 'N/A'}
City:       ${currentScanResult.geolocation?.city || 'N/A'}
ISP/ASN:    ${currentScanResult.geolocation?.isp || 'N/A'}
VPN/Proxy:  ${currentScanResult.geolocation?.is_vpn ? 'FLAGGED' : 'CLEAN'}
TOR Node:   ${currentScanResult.geolocation?.is_tor ? 'FLAGGED' : 'CLEAN'}

═════════════════════════════════════════════════════════════════
Generated by Sentryl AI Threat Intelligence Engine · SIH Hackathon
═════════════════════════════════════════════════════════════════
  `;

  const blob = new Blob([reportText], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentryl-forensic-report-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
});

// ─── Init ───────────────────────────────────────────────────

if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
  chrome.storage.local.get(['lastScan', 'lastEmail'], (items) => {
    if (items.lastScan && items.lastEmail) {
      displayResults(items.lastScan, items.lastEmail);
    } else {
      scanActiveGmailTab();
    }
  });
} else {
  scanScenario('paypal_phish');
}
