/**
 * service_worker.js - Manifest V3 Background Service Worker for PhishXcape
 * 
 * Main entry point for extension background lifecycle:
 * - Listens for tab navigations & URL updates
 * - Orchestrates local ML inference & online threat intel
 * - Handles communication with popup and content scripts
 */

importScripts(
  'utils/feature_extraction.js',
  'utils/random_forest_predict.js',
  'utils/threat_intel.js',
  'utils/decision_engine.js',
  'background.js'
);

const { scanTab, performScan, getCachedVerdict, updateBadge } = PhishXcapeBackground;

// Initialize on extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishXcape] Extension installed and service worker initialized.");
  PhishXcapeBackground.loadModel().catch((err) => {
    console.warn("[PhishXcape] Model pre-warm deferred:", err);
  });
});

// Monitor tab updates (navigation, URL change, reload)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    scanTab(tabId, tab.url);
  }
});

// Monitor active tab switching
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) {
      let verdict = getCachedVerdict(activeInfo.tabId);
      if (!verdict) {
        verdict = await scanTab(activeInfo.tabId, tab.url);
      } else {
        updateBadge(activeInfo.tabId, verdict);
      }
    }
  } catch (err) {
    // Tab might be transitional
  }
});

// Handle messages from Popup or Content Scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_TAB_VERDICT') {
    const tabId = request.tabId;
    const cached = getCachedVerdict(tabId);
    if (cached) {
      sendResponse({ status: 'SUCCESS', verdict: cached });
    } else {
      // Perform immediate scan
      scanTab(tabId, request.url).then((verdict) => {
        sendResponse({ status: 'SUCCESS', verdict });
      }).catch((err) => {
        sendResponse({ status: 'ERROR', error: err.message });
      });
      return true; // Keep message channel open for async response
    }
  } else if (request.type === 'TRIGGER_SCAN') {
    scanTab(request.tabId, request.url).then((verdict) => {
      sendResponse({ status: 'SUCCESS', verdict });
    }).catch((err) => {
      sendResponse({ status: 'ERROR', error: err.message });
    });
    return true;
  } else if (request.type === 'TEST_CUSTOM_URL') {
    performScan(request.url).then((verdict) => {
      sendResponse({ status: 'SUCCESS', verdict });
    }).catch((err) => {
      sendResponse({ status: 'ERROR', error: err.message });
    });
    return true;
  }
});
