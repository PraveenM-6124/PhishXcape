/**
 * test_detection.js - Multi-Layer Decision Engine & Edge Cases Test Suite
 * 
 * Run using: node tests/test_detection.js
 * 
 * Validates:
 * 1. Legitimate URLs (Safe)
 * 2. Phishing URLs detected via Safe Browsing
 * 3. Phishing URLs detected via VirusTotal
 * 4. High-confidence offline ML phishing alerts
 * 5. Suspicious URLs (moderate ML or single vendor VT flag)
 * 6. Offline capability (APIs disconnected/failed, ML still operates)
 * 7. Malformed / internal browser URLs
 */

const assert = require('assert');
const DecisionEngine = require('../extension/utils/decision_engine.js');

console.log("==========================================================");
console.log("PHISHXCAPE - MULTI-LAYER DECISION & SCENARIO TESTS");
console.log("==========================================================");

// Scenario 1: Legitimate Clean URL
console.log("\n[Scenario 1] Legitimate Website (All Checks Clean)");
const s1 = DecisionEngine.evaluateSecurityVerdict({
  url: "https://www.wikipedia.org",
  mlResult: { prediction: 0, verdict: "LEGITIMATE", confidenceScore: 88, phishingProbability: 0.12 },
  safeBrowsingResult: { isThreat: false, status: "CLEAN", details: "Clean" },
  virusTotalResult: { isThreat: false, isSuspicious: false, maliciousCount: 0, status: "CLEAN" }
});
console.log(`  Verdict: ${s1.status} | Threat Level: ${s1.threatLevel} | Badge: ${s1.badge}`);
assert.strictEqual(s1.status, "SAFE");
assert.strictEqual(s1.badgeColor, "#FFFFFF");

// Scenario 2: Google Safe Browsing Confirmed Phishing
console.log("\n[Scenario 2] Confirmed Phishing via Google Safe Browsing");
const s2 = DecisionEngine.evaluateSecurityVerdict({
  url: "http://malicious-credential-harvest.com/login",
  mlResult: { prediction: 1, verdict: "PHISHING", confidenceScore: 65, phishingProbability: 0.65 },
  safeBrowsingResult: { isThreat: true, status: "THREAT_DETECTED", threatTypes: ["SOCIAL_ENGINEERING"] },
  virusTotalResult: { isThreat: false, isSuspicious: false, maliciousCount: 0, status: "CLEAN" }
});
console.log(`  Verdict: ${s2.status} | Threat Level: ${s2.threatLevel} | Badge: ${s2.badge}`);
assert.strictEqual(s2.status, "PHISHING");
assert.strictEqual(s2.threatLevel, "Critical");
assert.strictEqual(s2.badgeColor, "#E50914");

// Scenario 3: VirusTotal Multi-Vendor Hit
console.log("\n[Scenario 3] Confirmed Phishing via VirusTotal Engines");
const s3 = DecisionEngine.evaluateSecurityVerdict({
  url: "http://fake-paypal-verify.account-security.ru",
  mlResult: { prediction: 0, verdict: "LEGITIMATE", confidenceScore: 55, phishingProbability: 0.45 },
  safeBrowsingResult: { isThreat: false, status: "CLEAN" },
  virusTotalResult: { isThreat: true, isSuspicious: true, maliciousCount: 9, status: "THREAT_DETECTED" }
});
console.log(`  Verdict: ${s3.status} | Threat Level: ${s3.threatLevel} | Badge: ${s3.badge}`);
assert.strictEqual(s3.status, "PHISHING");
assert.strictEqual(s3.threatLevel, "Critical");

// Scenario 4: Offline Operation (APIs Offline, High ML Phishing)
console.log("\n[Scenario 4] Offline Operation with High Confidence ML Phishing");
const s4 = DecisionEngine.evaluateSecurityVerdict({
  url: "http://deep-nested.sub.domain.attacker.com/very-long-path/index.php?token=xyz1234567890",
  mlResult: { prediction: 1, verdict: "PHISHING", confidenceScore: 92, phishingProbability: 0.92 },
  safeBrowsingResult: { isThreat: false, status: "OFFLINE", details: "Browser is offline." },
  virusTotalResult: { isThreat: false, status: "OFFLINE", details: "Browser is offline." }
});
console.log(`  Verdict: ${s4.status} | Threat Level: ${s4.threatLevel} | Badge: ${s4.badge}`);
assert.strictEqual(s4.status, "PHISHING");
assert.strictEqual(s4.threatLevel, "High");

// Scenario 5: Suspicious Heuristic (Moderate ML Score, No API threat)
console.log("\n[Scenario 5] Suspicious URL Flagged by ML Model");
const s5 = DecisionEngine.evaluateSecurityVerdict({
  url: "http://update-info-check.com/login",
  mlResult: { prediction: 1, verdict: "PHISHING", confidenceScore: 68, phishingProbability: 0.68 },
  safeBrowsingResult: { isThreat: false, status: "NOT_CONFIGURED" },
  virusTotalResult: { isThreat: false, status: "NOT_CONFIGURED" }
});
console.log(`  Verdict: ${s5.status} | Threat Level: ${s5.threatLevel} | Badge: ${s5.badge}`);
assert.strictEqual(s5.status, "SUSPICIOUS");
assert.strictEqual(s5.threatLevel, "Medium");

// Scenario 6: Internal Browser Pages & Invalid Targets
console.log("\n[Scenario 6] Internal Browser Page (chrome://settings)");
const s6 = DecisionEngine.evaluateSecurityVerdict({
  url: "chrome://settings",
  mlResult: null,
  safeBrowsingResult: null,
  virusTotalResult: null
});
console.log(`  Verdict: ${s6.status} | Headline: ${s6.headline}`);
assert.strictEqual(s6.status, "UNKNOWN");
assert.strictEqual(s6.badge, "BROWSER");

console.log("\n[+] test_detection.js: ALL MULTI-LAYER SCENARIO TESTS PASSED.");
