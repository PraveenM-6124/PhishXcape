/**
 * decision_engine.js - Multi-Layer Decision Policy for PhishXcape
 * 
 * Aggregates:
 * 1. Offline Random Forest ML prediction (Features + Tree consensus)
 * 2. Google Safe Browsing verification
 * 3. VirusTotal multi-vendor threat scan
 * 
 * Hierarchical Decision Policy:
 * - PHISHING (Red alert):
 *   Confirmed threat intelligence hit from Google Safe Browsing OR VirusTotal (>= 2 malicious),
 *   OR high confidence offline ML phishing prediction (confidence >= 80%).
 * 
 * - SUSPICIOUS (Red warning):
 *   ML model flagged phishing with moderate confidence (50% - 79%),
 *   OR single vendor hit on VirusTotal, without external confirmation.
 * 
 * - SAFE (Neutral / White check):
 *   ML model classified as Legitimate, no API threats found, and URL appears standard.
 * 
 * - UNKNOWN (Neutral):
 *   Special scheme (chrome://, about:blank, edge://, file://) or invalid/empty URL.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishXcapeDecision = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Evaluates the unified security verdict from multi-source evidence.
   * 
   * @param {Object} params
   * @param {string} params.url - Scanned URL
   * @param {Object} params.mlResult - Output from random_forest_predict.js
   * @param {Object} params.safeBrowsingResult - Output from Google Safe Browsing check
   * @param {Object} params.virusTotalResult - Output from VirusTotal check
   * @returns {Object} Comprehensive security verdict
   */
  function evaluateSecurityVerdict({ url, mlResult, safeBrowsingResult, virusTotalResult }) {
    if (!url || typeof url !== 'string' || !url.trim()) {
      return {
        status: "UNKNOWN",
        badge: "UNKNOWN",
        badgeColor: "#A1A1AA",
        threatLevel: "None",
        headline: "No Active Web Page",
        description: "PhishXcape could not read a valid web address.",
        recommendation: "Navigate to an HTTP/HTTPS website to initiate real-time inspection.",
        ml: mlResult || null,
        safeBrowsing: safeBrowsingResult || null,
        virusTotal: virusTotalResult || null,
        timestamp: new Date().toISOString()
      };
    }

    const lower = url.trim().toLowerCase();
    // Browser internal pages
    if (lower.startsWith('chrome://') || lower.startsWith('edge://') ||
        lower.startsWith('about:') || lower.startsWith('chrome-extension://')) {
      return {
        status: "UNKNOWN",
        badge: "BROWSER",
        badgeColor: "#A1A1AA",
        threatLevel: "None",
        headline: "Internal Browser Page",
        description: "Browser internal controls and settings pages are exempt from URL scanning.",
        recommendation: "PhishXcape will automatically monitor internet tabs.",
        ml: null,
        safeBrowsing: null,
        virusTotal: null,
        timestamp: new Date().toISOString()
      };
    }

    const hasSbThreat = safeBrowsingResult?.isThreat === true;
    const hasVtThreat = virusTotalResult?.isThreat === true;
    const isVtSuspicious = virusTotalResult?.isSuspicious === true;
    
    const mlIsPhish = mlResult?.prediction === 1;
    const mlConfidence = mlResult?.confidenceScore || 50;

    let finalStatus = "SAFE";
    let badgeColor = "#FFFFFF";
    let headline = "Website Verified Safe";
    let description = "No malicious patterns or threat records detected across available checks.";
    let recommendation = "Standard security practices apply. Continue browsing normally.";
    let threatLevel = "Low";

    // 1. High-severity Threat Intel Hit -> PHISHING
    if (hasSbThreat || hasVtThreat) {
      finalStatus = "PHISHING";
      badgeColor = "#E50914";
      threatLevel = "Critical";
      headline = "Dangerous Phishing Threat Detected!";
      
      const reasons = [];
      if (hasSbThreat) reasons.push("Google Safe Browsing threat match");
      if (hasVtThreat) reasons.push(`VirusTotal flagged by ${virusTotalResult.maliciousCount} security engines`);
      
      description = `Direct threat confirmed: ${reasons.join(" and ")}.`;
      recommendation = "Do NOT enter passwords, credit cards, or personal credentials. Close this tab immediately.";
    }
    // 2. High Confidence ML Prediction -> PHISHING
    else if (mlIsPhish && mlConfidence >= 80) {
      finalStatus = "PHISHING";
      badgeColor = "#E50914";
      threatLevel = "High";
      headline = "Potential Phishing Website Detected";
      description = `The Random Forest model identified high-probability deceptive URL patterns (Model score: ${mlConfidence}%).`;
      recommendation = "Exercise extreme caution. Verify the domain spelling before submitting any private information.";
    }
    // 3. Moderate Confidence ML or Minor Threat Flag -> SUSPICIOUS
    else if (mlIsPhish || isVtSuspicious) {
      finalStatus = "SUSPICIOUS";
      badgeColor = "#E50914"; // Primary Red warning highlight as per specs
      threatLevel = "Medium";
      headline = "Suspicious URL Characteristics Detected";
      
      if (mlIsPhish) {
        description = `The Random Forest model flagged anomalous URL length, subdomain nesting, or special character density (Model score: ${mlConfidence}%).`;
      } else {
        description = "Isolated security vendor flagged this URL as suspicious in threat intelligence databases.";
      }
      recommendation = "Check the address bar carefully for typosquatting or fake subdomains. Avoid downloading unexpected files.";
    }
    // 4. Clean URL
    else {
      finalStatus = "SAFE";
      badgeColor = "#FFFFFF"; // Clean white indicator
      threatLevel = "Low";
      headline = "No Threat Detected";
      description = `Passed offline Random Forest heuristic checks (Model score: ${mlConfidence}% legitimate).`;
      recommendation = "Always check that the website identity matches the service you expect.";
    }

    return {
      status: finalStatus,
      badge: finalStatus,
      badgeColor: badgeColor,
      threatLevel: threatLevel,
      headline: headline,
      description: description,
      recommendation: recommendation,
      ml: mlResult,
      safeBrowsing: safeBrowsingResult,
      virusTotal: virusTotalResult,
      timestamp: new Date().toISOString()
    };
  }

  return {
    evaluateSecurityVerdict
  };
}));
