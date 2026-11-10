/**
 * background.js - PhishXcape Core Background Controller Module
 * 
 * Orchestrates:
 * - Offline Model Loading and In-Memory Caching
 * - Feature Extraction Execution
 * - Threat Intelligence API Invocations (Google Safe Browsing & VirusTotal)
 * - Security Verdict Resolution
 * - Badge Updates and Content Script Notification
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishXcapeBackground = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  let cachedModel = null;
  const recentVerdicts = new Map(); // tabId -> verdict

  /**
   * Loads the exported Random Forest JSON model into memory.
   */
  async function loadModel() {
    if (cachedModel) return cachedModel;
    try {
      const modelUrl = chrome.runtime.getURL('model/random_forest_model.json');
      const response = await fetch(modelUrl);
      if (!response.ok) {
        throw new Error(`Failed to load model file: HTTP ${response.status}`);
      }
      cachedModel = await response.json();
      console.log(`[PhishXcape] Loaded Random Forest model with ${cachedModel.trees.length} trees.`);
      return cachedModel;
    } catch (e) {
      console.error("[PhishXcape] Model loading failed:", e);
      throw e;
    }
  }

  /**
   * Retrieves user API keys from chrome.storage.local safely.
   */
  async function getStoredApiKeys() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['googleSafeBrowsingKey', 'virusTotalKey'], (items) => {
        resolve({
          googleSafeBrowsingKey: items.googleSafeBrowsingKey || '',
          virusTotalKey: items.virusTotalKey || ''
        });
      });
    });
  }

  /**
   * Performs the complete multi-layer security scan on a URL.
   */
  async function performScan(url) {
    if (!url || !url.startsWith('http')) {
      return (self.PhishXcapeDecision || PhishXcapeDecision).evaluateSecurityVerdict({
        url, mlResult: null, safeBrowsingResult: null, virusTotalResult: null
      });
    }

    // 1. Ensure Model is ready
    const model = await loadModel();

    // 2. Extract 4 URL Features
    const featuresModule = self.PhishXcapeFeatures || PhishXcapeFeatures;
    const features = featuresModule.extractFeatures(url);

    // 3. Offline Random Forest Inference
    const mlEngine = self.PhishXcapeModel || PhishXcapeModel;
    const mlResult = mlEngine.predict(model, features);

    // 4. Retrieve API keys
    const keys = await getStoredApiKeys();

    // 5. Threat Intelligence APIs in parallel
    const threatIntel = self.PhishXcapeThreatIntel || PhishXcapeThreatIntel;
    const [safeBrowsingResult, virusTotalResult] = await Promise.all([
      threatIntel.checkGoogleSafeBrowsing(url, keys.googleSafeBrowsingKey),
      threatIntel.checkVirusTotal(url, keys.virusTotalKey)
    ]);

    // 6. Aggregate into Unified Verdict
    const decisionEngine = self.PhishXcapeDecision || PhishXcapeDecision;
    const verdict = decisionEngine.evaluateSecurityVerdict({
      url,
      mlResult,
      safeBrowsingResult,
      virusTotalResult
    });

    return verdict;
  }

  /**
   * Updates Chrome Extension Toolbar Action Badge
   */
  function updateBadge(tabId, verdict) {
    if (!tabId || !verdict) return;

    let text = "";
    let bgColor = "#33333D";

    switch (verdict.status) {
      case "PHISHING":
        text = "!";
        bgColor = "#E50914"; // Red alert
        break;
      case "SUSPICIOUS":
        text = "?";
        bgColor = "#B20710"; // Dark red warning
        break;
      case "SAFE":
        text = "✓";
        bgColor = "#1C1C24"; // Neutral dark card
        break;
      default:
        text = "";
        bgColor = "#33333D";
        break;
    }

    try {
      chrome.action.setBadgeText({ tabId, text });
      chrome.action.setBadgeBackgroundColor({ tabId, color: bgColor });
    } catch (e) {
      // Tab may be closed or navigation aborted
    }
  }

  /**
   * Scans tab and notifies in-page content script if phishing is detected.
   */
  async function scanTab(tabId, url) {
    if (!url || !url.startsWith('http')) return null;

    try {
      const verdict = await performScan(url);
      recentVerdicts.set(tabId, verdict);
      updateBadge(tabId, verdict);

      // If suspicious or phishing, notify content script to present alert banner
      if (verdict.status === "PHISHING" || verdict.status === "SUSPICIOUS") {
        try {
          chrome.tabs.sendMessage(tabId, {
            type: "PHISHXCAPE_ALERT",
            verdict: verdict
          });
        } catch (e) {
          // Content script may not have injected yet
        }
      }

      return verdict;
    } catch (err) {
      console.error("[PhishXcape] Tab scan error:", err);
      return null;
    }
  }

  function getCachedVerdict(tabId) {
    return recentVerdicts.get(tabId) || null;
  }

  return {
    loadModel,
    getStoredApiKeys,
    performScan,
    updateBadge,
    scanTab,
    getCachedVerdict
  };
}));
