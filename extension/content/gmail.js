/**
 * Sentryl — Gmail In-Page Inspector & Threat Simulation Injector
 * 100% Pure Client-Side JavaScript
 */

(() => {
  'use strict';

  // Inject detector engine if not already present
  const detector = new SentrylDetector();

  // ─── Extractors for Real Gmail DOM ────────────────────────

  function extractUrls(text) {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s<>"')\]},;]+/gi;
    return [...new Set(text.match(urlRegex) || [])];
  }

  function extractEmails(text) {
    if (!text) return [];
    const emailRegex = /[\w.+-]+@[\w-]+\.[\w.-]+/gi;
    return [...new Set(text.match(emailRegex) || [])];
  }

  function getSenderEmail() {
    const fromSpans = document.querySelectorAll('span[email]');
    for (const span of fromSpans) {
      const email = span.getAttribute('email');
      if (email && email.includes('@')) return email;
    }

    const headerTable = document.querySelector('table.Bs.nH .gE') || document.querySelector('.ha') || document.querySelector('.nH.aHU');
    if (headerTable) {
      const emails = extractEmails(headerTable.textContent);
      if (emails.length > 0) return emails[0];
    }
    return 'unknown-sender@mail.net';
  }

  function getSenderName() {
    const span = document.querySelector('span[email]');
    if (span) {
      return span.getAttribute('name') || span.textContent?.trim() || null;
    }
    const h3 = document.querySelector('.gD');
    return h3?.textContent?.trim() || 'Sender';
  }

  function getSubject() {
    const subjectEl = document.querySelector('h2.hP') || document.querySelector('.ha h2');
    return subjectEl?.textContent?.trim() || 'Untitled Email';
  }

  function getBodyText() {
    const bodies = document.querySelectorAll('div.a3s.aiL');
    if (bodies.length > 0) {
      return bodies[bodies.length - 1]?.textContent?.trim() || '';
    }
    const altBodies = document.querySelectorAll('div[data-message-id] div.a3s');
    if (altBodies.length > 0) {
      return altBodies[altBodies.length - 1]?.textContent?.trim() || '';
    }
    return '';
  }

  function getEmailUrls() {
    const bodyText = getBodyText();
    const textUrls = extractUrls(bodyText);
    const bodies = document.querySelectorAll('div.a3s.aiL');
    const hrefUrls = [];
    if (bodies.length > 0) {
      const links = bodies[bodies.length - 1].querySelectorAll('a[href]');
      links.forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http')) {
          if (href.includes('google.com/url')) {
            try {
              const url = new URL(href);
              const realUrl = url.searchParams.get('q');
              if (realUrl) hrefUrls.push(realUrl);
            } catch (_) {
              hrefUrls.push(href);
            }
          } else {
            hrefUrls.push(href);
          }
        }
      });
    }
    return [...new Set([...textUrls, ...hrefUrls])];
  }

  function isEmailOpen() {
    return !!document.querySelector('div.a3s.aiL') || !!document.querySelector('h2.hP');
  }

  // ─── Floating Sentryl Quick Control Bar ───────────────────

  function createFloatingControls() {
    if (document.getElementById('sentryl-floating-bar')) return;

    const bar = document.createElement('div');
    bar.id = 'sentryl-floating-bar';
    bar.innerHTML = `
      <div class="sentryl-float-inner">
        <div class="sentryl-float-brand">
          <svg viewBox="0 0 32 32" fill="none" class="sentryl-float-logo">
            <path d="M16 3 27 8v9c0 8-5 12.5-11 13-6-.5-11-5-11-13V8L16 3Z" stroke="#3fe8d4" stroke-width="2"/>
            <path d="M9 16h14" stroke="#3fe8d4" stroke-width="2" opacity="0.6"/>
            <circle cx="9" cy="16" r="1.5" fill="#3fe8d4"/>
          </svg>
          <span class="sentryl-float-title">Sentryl AI</span>
        </div>

        <button id="sentryl-btn-scan-real" class="sentryl-btn-action" title="Scan email currently open in Gmail">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m10 15 5-3-5-3v6z"/></svg>
          Scan Open Email
        </button>

        <div class="sentryl-sim-dropdown">
          <button id="sentryl-btn-sim-toggle" class="sentryl-btn-secondary">
            🧪 Inject Scenario ▾
          </button>
          <div class="sentryl-sim-menu" id="sentryl-sim-menu">
            <div class="sentryl-sim-header">SIH Live Demo Scenarios:</div>
            <div class="sentryl-sim-item" data-id="paypal_phish">
              <span class="sentryl-sim-tag danger">High Risk</span>
              <span class="sentryl-sim-name">PayPal Spoof & IP Link</span>
            </div>
            <div class="sentryl-sim-item" data-id="bec_wire">
              <span class="sentryl-sim-tag danger">BEC</span>
              <span class="sentryl-sim-name">CEO Wire Transfer Fraud</span>
            </div>
            <div class="sentryl-sim-item" data-id="ms365_creds">
              <span class="sentryl-sim-tag warn">Harvesting</span>
              <span class="sentryl-sim-name">Microsoft 365 Pass Expiry</span>
            </div>
            <div class="sentryl-sim-item" data-id="legit_google">
              <span class="sentryl-sim-tag safe">Clean</span>
              <span class="sentryl-sim-name">Legitimate Google Alert</span>
            </div>
          </div>
        </div>

        <button id="sentryl-btn-open-report" class="sentryl-btn-ghost" title="Open Forensic Intelligence Report">
          📊 Forensics
        </button>
      </div>
    `;

    document.body.appendChild(bar);

    // Event listeners
    const simMenu = document.getElementById('sentryl-sim-menu');
    const simToggle = document.getElementById('sentryl-btn-sim-toggle');

    simToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      simMenu.classList.toggle('show');
    });

    document.addEventListener('click', () => {
      simMenu.classList.remove('show');
    });

    document.getElementById('sentryl-btn-scan-real').addEventListener('click', () => {
      scanCurrentOpenEmail();
    });

    document.querySelectorAll('.sentryl-sim-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const scenarioId = item.getAttribute('data-id');
        injectAndScanScenario(scenarioId);
        simMenu.classList.remove('show');
      });
    });

    document.getElementById('sentryl-btn-open-report').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'openReportPage' });
    });
  }

  // ─── Inline Banner Injection ──────────────────────────────

  const BANNER_ID = 'sentryl-risk-banner';

  function removeBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
  }

  function injectBanner(result, emailData) {
    removeBanner();

    const score = result.risk_score;
    const level = score >= 70 ? 'danger' : score >= 40 ? 'warn' : 'safe';
    const label = score >= 70 ? 'HIGH THREAT DETECTED' : score >= 40 ? 'SUSPICIOUS INDICATORS' : 'CLEAN & VERIFIED';

    const failChecks = result.checks.filter(c => c.status === 'fail' || c.status === 'warn');
    const topDetail = failChecks.length > 0 ? failChecks[0].detail : 'No malicious links, spoofing, or authentication anomalies detected.';

    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.className = `sentryl-injected-banner ${level}`;
    banner.innerHTML = `
      <div class="sentryl-banner-top">
        <div class="sentryl-banner-score ${level}">
          <span class="sentryl-score-val">${score}</span>
          <span class="sentryl-score-label">/ 100 RISK</span>
        </div>
        <div class="sentryl-banner-info">
          <div class="sentryl-banner-title ${level}">
            ${level === 'danger' ? '🚨' : level === 'warn' ? '⚠️' : '🛡️'} Sentryl Shield: ${label}
          </div>
          <div class="sentryl-banner-desc">${escapeHtml(topDetail)}</div>
        </div>
        <div class="sentryl-banner-actions">
          <button class="sentryl-view-report-btn" id="sentryl-btn-deep-forensic">
            View Full Forensics & Map ➔
          </button>
          <button class="sentryl-close-btn" id="sentryl-close-banner">✕</button>
        </div>
      </div>
      <div class="sentryl-banner-checks">
        ${result.checks.slice(0, 3).map(c => `
          <div class="sentryl-mini-check ${c.status}">
            <span class="sentryl-check-icon">${c.status === 'fail' ? '✕' : c.status === 'warn' ? '⚠' : '✓'}</span>
            <span class="sentryl-check-name">${escapeHtml(c.name)}</span>
          </div>
        `).join('')}
      </div>
    `;

    const messageBody = document.querySelector('div.a3s.aiL') || document.querySelector('.ha');
    if (messageBody && messageBody.parentElement) {
      messageBody.parentElement.insertBefore(banner, messageBody);
    } else {
      document.body.prepend(banner);
    }

    // Bind forensic report button
    document.getElementById('sentryl-btn-deep-forensic')?.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'openReportPage' });
    });

    document.getElementById('sentryl-close-banner')?.addEventListener('click', removeBanner);
  }

  // ─── Scan Functions ───────────────────────────────────────

  async function scanCurrentOpenEmail() {
    const emailData = {
      sender: getSenderEmail(),
      senderName: getSenderName(),
      subject: getSubject(),
      body: getBodyText(),
      urls: getEmailUrls(),
      headers: '',
      replyTo: ''
    };

    const result = await detector.scan(emailData);

    // Save to storage for popup and dashboard
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ lastScan: result, lastEmail: emailData });
    }

    injectBanner(result, emailData);
    return result;
  }

  async function injectAndScanScenario(scenarioKey) {
    const scenario = SENTRYL_SCENARIOS[scenarioKey];
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

    // Save in storage
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ lastScan: result, lastEmail: emailData });
    }

    injectBanner(result, emailData);
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ─── Message Listener ─────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'extractEmail') {
      const emailData = {
        sender: getSenderEmail(),
        senderName: getSenderName(),
        subject: getSubject(),
        body: getBodyText(),
        urls: getEmailUrls(),
        replyTo: '',
        headers: ''
      };
      sendResponse(emailData);
      return true;
    }

    if (msg.action === 'runScenario' && msg.scenarioId) {
      injectAndScanScenario(msg.scenarioId);
      sendResponse({ ok: true });
      return true;
    }
  });

  // ─── Initialization ───────────────────────────────────────

  function init() {
    createFloatingControls();

    // Observe navigation in Gmail
    let lastUrl = location.href;
    const observer = new MutationObserver(() => {
      createFloatingControls();
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        removeBanner();
        if (isEmailOpen()) {
          setTimeout(scanCurrentOpenEmail, 1000);
        }
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });

    if (isEmailOpen()) {
      setTimeout(scanCurrentOpenEmail, 1200);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  console.log('[Sentryl] In-page AI Forensic Engine & Demo Injector initialized.');
})();
