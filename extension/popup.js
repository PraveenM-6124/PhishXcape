/**
 * popup.js - PhishXcape Extension Popup Controller
 * 
 * Manages UI interactions, tab scanning, details accordion,
 * live URL testing, and threat intelligence key management.
 */

document.addEventListener('DOMContentLoaded', () => {
  let currentActiveTab = null;
  let currentVerdict = null;

  // DOM Elements
  const elSiteHostname = document.getElementById('site-hostname');
  const elSiteUrl = document.getElementById('site-url');
  const elScanTimestamp = document.getElementById('scan-timestamp');
  
  const elStatusCard = document.getElementById('status-card');
  const elStatusBadge = document.getElementById('status-badge');
  const elStatusThreatLevel = document.getElementById('status-threat-level');
  const elStatusHeadline = document.getElementById('status-headline');
  const elStatusDesc = document.getElementById('status-description');

  const elAlertBox = document.getElementById('alert-box');
  const elAlertText = document.getElementById('alert-text');

  const elBtnToggleDetails = document.getElementById('btn-toggle-details');
  const elDetectionDetails = document.getElementById('detection-details');
  const elDetailsArrow = document.getElementById('details-arrow');

  const elMlBadge = document.getElementById('ml-badge');
  const elMlConfidence = document.getElementById('ml-confidence');
  const elFeatHttps = document.getElementById('feat-https');
  const elFeatLen = document.getElementById('feat-len');
  const elFeatSubs = document.getElementById('feat-subs');
  const elFeatChars = document.getElementById('feat-chars');

  const elGsbBadge = document.getElementById('gsb-badge');
  const elGsbDetails = document.getElementById('gsb-details');

  const elVtBadge = document.getElementById('vt-badge');
  const elVtMaliciousCount = document.getElementById('vt-malicious-count');
  const elVtDetails = document.getElementById('vt-details');

  const elCustomInput = document.getElementById('custom-url-input');
  const elBtnCustomScan = document.getElementById('btn-custom-scan');

  const elBtnScanCurrent = document.getElementById('btn-scan-current');
  const elBtnRefresh = document.getElementById('btn-refresh');

  // Settings Drawer Elements
  const elBtnSettingsToggle = document.getElementById('btn-settings-toggle');
  const elSettingsDrawer = document.getElementById('settings-drawer');
  const elBtnCloseSettings = document.getElementById('btn-close-settings');
  const elInputGsbKey = document.getElementById('input-gsb-key');
  const elInputVtKey = document.getElementById('input-vt-key');
  const elBtnSaveKeys = document.getElementById('btn-save-keys');
  const elBtnClearKeys = document.getElementById('btn-clear-keys');
  const elSettingsStatusMsg = document.getElementById('settings-status-msg');

  /**
   * Initializes Popup and triggers active tab scan
   */
  async function init() {
    loadStoredKeys();
    
    // Retrieve active tab
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0]) {
        currentActiveTab = tabs[0];
        displayTabMetadata(currentActiveTab.url);
        requestTabScan(currentActiveTab.id, currentActiveTab.url);
      } else {
        renderUnknownState("No active browser window detected.");
      }
    } catch (err) {
      console.error("[PhishXcape] Tab query failed:", err);
      renderUnknownState("Browser permissions restricted.");
    }
  }

  function displayTabMetadata(url) {
    if (!url) {
      elSiteHostname.textContent = "Unknown Host";
      elSiteUrl.textContent = "about:blank";
      return;
    }

    try {
      const parsed = new URL(url);
      elSiteHostname.textContent = parsed.hostname || "Internal Target";
    } catch (e) {
      elSiteHostname.textContent = url.split('/')[0] || "Custom Target";
    }

    elSiteUrl.textContent = url;
    elScanTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  /**
   * Dispatches scan request to background service worker
   */
  function requestTabScan(tabId, url) {
    setLoadingState();

    chrome.runtime.sendMessage({
      type: 'GET_TAB_VERDICT',
      tabId: tabId,
      url: url
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[PhishXcape] Service worker communication error:", chrome.runtime.lastError.message);
        // Fallback: perform direct client-side evaluation if available
        fallbackDirectScan(url);
        return;
      }

      if (response && response.status === 'SUCCESS' && response.verdict) {
        currentVerdict = response.verdict;
        renderVerdict(response.verdict);
      } else {
        renderUnknownState("Could not verify URL safety.");
      }
    });
  }

  /**
   * Client-side fallback if service worker is waking up or detached
   */
  async function fallbackDirectScan(url) {
    try {
      const modelResp = await fetch(chrome.runtime.getURL('model/random_forest_model.json'));
      const modelJson = await modelResp.json();
      const features = PhishXcapeFeatures.extractFeatures(url);
      const mlResult = PhishXcapeModel.predict(modelJson, features);

      const verdict = {
        status: mlResult.prediction === 1 ? (mlResult.confidenceScore >= 80 ? "PHISHING" : "SUSPICIOUS") : "SAFE",
        badge: mlResult.prediction === 1 ? (mlResult.confidenceScore >= 80 ? "PHISHING" : "SUSPICIOUS") : "SAFE",
        badgeColor: mlResult.prediction === 1 ? "#E50914" : "#FFFFFF",
        threatLevel: mlResult.prediction === 1 ? "Elevated" : "Low",
        headline: mlResult.prediction === 1 ? "Potential Phishing Detected (Offline ML)" : "Website Verified Safe (Offline ML)",
        description: `Offline Random Forest evaluated 4 URL heuristics with ${mlResult.confidenceScore}% consensus.`,
        recommendation: mlResult.prediction === 1 ? "Verify URL authenticity before entering credentials." : "Standard browsing security applies.",
        ml: mlResult,
        safeBrowsing: { status: "OFFLINE", details: "Online threat intel unavailable." },
        virusTotal: { status: "OFFLINE", details: "Online threat intel unavailable." }
      };

      currentVerdict = verdict;
      renderVerdict(verdict);
    } catch (e) {
      renderUnknownState("Offline inference error.");
    }
  }

  function setLoadingState() {
    elStatusCard.className = "status-card status-loading";
    elStatusBadge.textContent = "SCANNING";
    elStatusBadge.style.backgroundColor = "#1C1C24";
    elStatusBadge.style.color = "#FFFFFF";
    elStatusThreatLevel.textContent = "Evaluating...";
    elStatusHeadline.textContent = "Analyzing URL Security...";
    elStatusDesc.textContent = "Checking Random Forest model and threat feeds...";
    elAlertBox.style.display = "none";
  }

  function renderVerdict(verdict) {
    elScanTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // Status Card Classes
    elStatusCard.className = "status-card";
    if (verdict.status === 'PHISHING') {
      elStatusCard.classList.add('status-phishing');
    } else if (verdict.status === 'SUSPICIOUS') {
      elStatusCard.classList.add('status-suspicious');
    } else if (verdict.status === 'SAFE') {
      elStatusCard.classList.add('status-safe');
    }

    elStatusBadge.textContent = verdict.status;
    elStatusThreatLevel.textContent = `Threat Level: ${verdict.threatLevel}`;
    elStatusHeadline.textContent = verdict.headline;
    elStatusDesc.textContent = verdict.description;

    // Alert Box
    if (verdict.status === 'PHISHING' || verdict.status === 'SUSPICIOUS') {
      elAlertBox.style.display = 'flex';
      elAlertText.textContent = verdict.recommendation;
    } else {
      elAlertBox.style.display = 'none';
    }

    // ML Card Details
    if (verdict.ml) {
      const ml = verdict.ml;
      elMlBadge.textContent = ml.verdict;
      elMlBadge.className = ml.prediction === 1 ? 'pill pill-danger' : 'pill pill-safe';
      elMlConfidence.textContent = `${ml.confidenceScore}% (${ml.verdict})`;

      if (ml.featureValues && ml.featureValues.length === 4) {
        elFeatHttps.textContent = ml.featureValues[0] === 1 ? 'Yes (1)' : 'No (0)';
        elFeatLen.textContent = `${ml.featureValues[1]} chars`;
        elFeatSubs.textContent = `${ml.featureValues[2]}`;
        elFeatChars.textContent = `${ml.featureValues[3]}`;
      }
    } else {
      elMlBadge.textContent = "N/A";
      elMlBadge.className = "pill pill-neutral";
      elMlConfidence.textContent = "--%";
    }

    // Google Safe Browsing Details
    if (verdict.safeBrowsing) {
      const gsb = verdict.safeBrowsing;
      elGsbBadge.textContent = gsb.status.replace(/_/g, ' ');
      if (gsb.status === 'THREAT_DETECTED') {
        elGsbBadge.className = 'pill pill-danger';
      } else if (gsb.status === 'CLEAN') {
        elGsbBadge.className = 'pill pill-safe';
      } else {
        elGsbBadge.className = 'pill pill-neutral';
      }
      elGsbDetails.textContent = gsb.details;
    }

    // VirusTotal Details
    if (verdict.virusTotal) {
      const vt = verdict.virusTotal;
      elVtBadge.textContent = vt.status.replace(/_/g, ' ');
      if (vt.status === 'THREAT_DETECTED') {
        elVtBadge.className = 'pill pill-danger';
      } else if (vt.status === 'SUSPICIOUS') {
        elVtBadge.className = 'pill pill-warning';
      } else if (vt.status === 'CLEAN') {
        elVtBadge.className = 'pill pill-safe';
      } else {
        elVtBadge.className = 'pill pill-neutral';
      }
      elVtMaliciousCount.textContent = `${vt.maliciousCount || 0} engines`;
      elVtDetails.textContent = vt.details;
    }
  }

  function renderUnknownState(reason) {
    elStatusCard.className = "status-card";
    elStatusBadge.textContent = "UNKNOWN";
    elStatusThreatLevel.textContent = "Threat: None";
    elStatusHeadline.textContent = "Inspection Inactive";
    elStatusDesc.textContent = reason;
    elAlertBox.style.display = "none";
  }

  // Toggle Details
  elBtnToggleDetails.addEventListener('click', () => {
    const isHidden = elDetectionDetails.style.display === 'none';
    elDetectionDetails.style.display = isHidden ? 'flex' : 'none';
    elDetailsArrow.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
    elBtnToggleDetails.querySelector('span').textContent = isHidden ? 'Hide Detection Details' : 'View Detection Details';
  });

  // Action Buttons
  elBtnScanCurrent.addEventListener('click', () => {
    if (currentActiveTab && currentActiveTab.url) {
      requestTabScan(currentActiveTab.id, currentActiveTab.url);
    }
  });

  elBtnRefresh.addEventListener('click', () => {
    if (currentActiveTab && currentActiveTab.url) {
      requestTabScan(currentActiveTab.id, currentActiveTab.url);
    }
  });

  // Custom URL Quick Tester
  elBtnCustomScan.addEventListener('click', () => {
    const testUrl = elCustomInput.value.trim();
    if (!testUrl) return;

    displayTabMetadata(testUrl);
    setLoadingState();

    chrome.runtime.sendMessage({
      type: 'TEST_CUSTOM_URL',
      url: testUrl
    }, (response) => {
      if (response && response.status === 'SUCCESS' && response.verdict) {
        renderVerdict(response.verdict);
      } else {
        fallbackDirectScan(testUrl);
      }
    });
  });

  elCustomInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      elBtnCustomScan.click();
    }
  });

  // Settings Drawer Toggle
  elBtnSettingsToggle.addEventListener('click', () => {
    elSettingsDrawer.style.display = 'flex';
  });

  elBtnCloseSettings.addEventListener('click', () => {
    elSettingsDrawer.style.display = 'none';
    elSettingsStatusMsg.textContent = '';
  });

  function loadStoredKeys() {
    chrome.storage.local.get(['googleSafeBrowsingKey', 'virusTotalKey'], (items) => {
      if (items.googleSafeBrowsingKey) elInputGsbKey.value = items.googleSafeBrowsingKey;
      if (items.virusTotalKey) elInputVtKey.value = items.virusTotalKey;
    });
  }

  elBtnSaveKeys.addEventListener('click', () => {
    const gsb = elInputGsbKey.value.trim();
    const vt = elInputVtKey.value.trim();

    chrome.storage.local.set({
      googleSafeBrowsingKey: gsb,
      virusTotalKey: vt
    }, () => {
      elSettingsStatusMsg.style.color = '#FFFFFF';
      elSettingsStatusMsg.textContent = 'API keys saved securely in local storage.';
      setTimeout(() => {
        elSettingsDrawer.style.display = 'none';
        elSettingsStatusMsg.textContent = '';
        // Re-scan with new keys
        if (currentActiveTab && currentActiveTab.url) {
          requestTabScan(currentActiveTab.id, currentActiveTab.url);
        }
      }, 1000);
    });
  });

  elBtnClearKeys.addEventListener('click', () => {
    chrome.storage.local.remove(['googleSafeBrowsingKey', 'virusTotalKey'], () => {
      elInputGsbKey.value = '';
      elInputVtKey.value = '';
      elSettingsStatusMsg.style.color = '#A1A1AA';
      elSettingsStatusMsg.textContent = 'API keys cleared.';
    });
  });

  init();
});
