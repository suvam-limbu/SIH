/**
 * Sentryl — Background Service Worker (Manifest V3)
 * Pure Client-Side Coordination
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('[Sentryl] Background Service Worker ready.');
  chrome.action.setBadgeText({ text: 'AI' });
  chrome.action.setBadgeBackgroundColor({ color: '#3fe8d4' });
});

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'openReportPage') {
    chrome.tabs.create({
      url: chrome.runtime.getURL('dashboard/report.html')
    });
    sendResponse({ ok: true });
    return true;
  }

  if (request.action === 'updateBadge' && request.score !== undefined) {
    const score = request.score;
    if (score >= 70) {
      chrome.action.setBadgeText({ text: String(score) });
      chrome.action.setBadgeBackgroundColor({ color: '#ff5c6c' });
    } else if (score >= 40) {
      chrome.action.setBadgeText({ text: String(score) });
      chrome.action.setBadgeBackgroundColor({ color: '#f5c563' });
    } else {
      chrome.action.setBadgeText({ text: '✓' });
      chrome.action.setBadgeBackgroundColor({ color: '#3fe8d4' });
    }
    sendResponse({ ok: true });
    return true;
  }
});
