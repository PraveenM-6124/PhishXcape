/**
 * threat_intel.js - Threat Intelligence Integration for PhishXcape
 * 
 * Handles:
 * 1. Google Safe Browsing Lookup API (v4)
 * 2. VirusTotal REST API (v3)
 * 
 * Security Principles:
 * - Never hardcodes API keys in public code.
 * - Keys are retrieved dynamically from chrome.storage.local (configured by user).
 * - Fails safely: API unavailability or network timeouts are marked as UNAVAILABLE,
 *   never falsely inferred as "SAFE".
 * - Offline-friendly: gracefully falls back when navigator.onLine is false or network fails.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishXcapeThreatIntel = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Encodes a URL to VirusTotal v3 URL identifier:
   * Base64 of the URL string without trailing '=' padding characters.
   */
  function getVirusTotalUrlId(url) {
    try {
      // In browser / web worker environment
      let base64;
      if (typeof btoa === 'function') {
        base64 = btoa(unescape(encodeURIComponent(url)));
      } else if (typeof Buffer !== 'undefined') {
        base64 = Buffer.from(url).toString('base64');
      } else {
        throw new Error("Base64 encoder unavailable.");
      }
      return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    } catch (e) {
      console.error("[PhishXcape] VT URL encoding error:", e);
      return null;
    }
  }

  /**
   * Queries Google Safe Browsing v4 ThreatMatches API.
   * 
   * @param {string} url - Target URL
   * @param {string} apiKey - Safe Browsing API Key
   * @returns {Promise<Object>} Verification status & matches
   */
  async function checkGoogleSafeBrowsing(url, apiKey) {
    if (!apiKey) {
      return {
        service: "Google Safe Browsing",
        status: "NOT_CONFIGURED",
        isThreat: false,
        threatTypes: [],
        details: "API key not set in extension settings."
      };
    }

    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      return {
        service: "Google Safe Browsing",
        status: "OFFLINE",
        isThreat: false,
        threatTypes: [],
        details: "Browser is offline."
      };
    }

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
    const requestBody = {
      client: {
        clientId: "phishxcape-extension",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (response.status === 429) {
        return {
          service: "Google Safe Browsing",
          status: "RATE_LIMITED",
          isThreat: false,
          threatTypes: [],
          details: "Rate limit exceeded. Try again later."
        };
      }

      if (!response.ok) {
        return {
          service: "Google Safe Browsing",
          status: "ERROR",
          isThreat: false,
          threatTypes: [],
          details: `HTTP ${response.status}: API request failed.`
        };
      }

      const data = await response.json();
      const matches = data.matches || [];

      if (matches.length > 0) {
        const types = matches.map(m => m.threatType);
        return {
          service: "Google Safe Browsing",
          status: "THREAT_DETECTED",
          isThreat: true,
          threatTypes: types,
          details: `Identified threat: ${types.join(", ")}`
        };
      }

      return {
        service: "Google Safe Browsing",
        status: "CLEAN",
        isThreat: false,
        threatTypes: [],
        details: "No known threats found in Safe Browsing registry."
      };

    } catch (err) {
      return {
        service: "Google Safe Browsing",
        status: "UNAVAILABLE",
        isThreat: false,
        threatTypes: [],
        details: err.name === 'AbortError' ? "Request timed out." : "Network error / offline."
      };
    }
  }

  /**
   * Queries VirusTotal v3 REST API for URL analysis.
   * 
   * @param {string} url - Target URL
   * @param {string} apiKey - VirusTotal API Key
   * @returns {Promise<Object>} Analysis statistics & malicious count
   */
  async function checkVirusTotal(url, apiKey) {
    if (!apiKey) {
      return {
        service: "VirusTotal",
        status: "NOT_CONFIGURED",
        isThreat: false,
        maliciousCount: 0,
        suspiciousCount: 0,
        harmlessCount: 0,
        details: "API key not set in extension settings."
      };
    }

    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      return {
        service: "VirusTotal",
        status: "OFFLINE",
        isThreat: false,
        maliciousCount: 0,
        suspiciousCount: 0,
        harmlessCount: 0,
        details: "Browser is offline."
      };
    }

    const urlId = getVirusTotalUrlId(url);
    if (!urlId) {
      return {
        service: "VirusTotal",
        status: "ERROR",
        isThreat: false,
        maliciousCount: 0,
        suspiciousCount: 0,
        harmlessCount: 0,
        details: "Could not generate VirusTotal URL identifier."
      };
    }

    const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(endpoint, {
        method: "GET",
        headers: {
          "x-apikey": apiKey,
          "Accept": "application/json"
        },
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (response.status === 404) {
        return {
          service: "VirusTotal",
          status: "NOT_ANALYZED",
          isThreat: false,
          maliciousCount: 0,
          suspiciousCount: 0,
          harmlessCount: 0,
          details: "URL not yet indexed by VirusTotal."
        };
      }

      if (response.status === 429) {
        return {
          service: "VirusTotal",
          status: "RATE_LIMITED",
          isThreat: false,
          maliciousCount: 0,
          suspiciousCount: 0,
          harmlessCount: 0,
          details: "VirusTotal rate limit reached (4 req/min for free tier)."
        };
      }

      if (!response.ok) {
        return {
          service: "VirusTotal",
          status: "ERROR",
          isThreat: false,
          maliciousCount: 0,
          suspiciousCount: 0,
          harmlessCount: 0,
          details: `HTTP ${response.status}: API request failed.`
        };
      }

      const data = await response.json();
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;

      const isThreat = malicious >= 2 || (malicious >= 1 && suspicious >= 1);
      const isSuspicious = !isThreat && (malicious === 1 || suspicious >= 1);

      return {
        service: "VirusTotal",
        status: isThreat ? "THREAT_DETECTED" : (isSuspicious ? "SUSPICIOUS" : "CLEAN"),
        isThreat: isThreat,
        isSuspicious: isSuspicious,
        maliciousCount: malicious,
        suspiciousCount: suspicious,
        harmlessCount: harmless,
        details: `${malicious} security vendor(s) flagged this URL as malicious.`
      };

    } catch (err) {
      return {
        service: "VirusTotal",
        status: "UNAVAILABLE",
        isThreat: false,
        maliciousCount: 0,
        suspiciousCount: 0,
        harmlessCount: 0,
        details: err.name === 'AbortError' ? "Request timed out." : "Network error / offline."
      };
    }
  }

  return {
    getVirusTotalUrlId,
    checkGoogleSafeBrowsing,
    checkVirusTotal
  };
}));
