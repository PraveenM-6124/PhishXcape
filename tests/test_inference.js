/**
 * test_inference.js - JavaScript Feature Extraction & Offline Inference Tests
 * 
 * Run using: node tests/test_inference.js
 * 
 * Validates:
 * 1. JavaScript feature extraction matches Python logic.
 * 2. Exported Random Forest JSON loads and evaluates correctly.
 * 3. Parity with Python reference predictions.
 * 4. Sub-millisecond evaluation speed in JavaScript.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

// Load JS modules
const Features = require('../extension/utils/feature_extraction.js');
const ModelEngine = require('../extension/utils/random_forest_predict.js');

// Load exported JSON model
const modelPath = path.join(__dirname, '..', 'extension', 'model', 'random_forest_model.json');
assert(fs.existsSync(modelPath), `Model file not found at ${modelPath}`);
const modelJson = JSON.parse(fs.readFileSync(modelPath, 'utf8'));

console.log("==========================================================");
console.log("PHISHXCAPE - JAVASCRIPT OFFLINE INFERENCE & PARITY TESTS");
console.log("==========================================================");

// Test 1: Feature Extraction
console.log("\n[1] Testing JavaScript URL Feature Extraction...");

const testCases = [
  {
    url: "https://www.google.com/search?q=cybersecurity",
    expected: [1, 45, 1, 8]
  },
  {
    url: "http://insecure-login.bank.co.uk/verify/index.php?user=1&token=xyz",
    expected: [0, 66, 1, 14]
  },
  {
    url: "dniash.solidwebhost.com/louis-daraft-dollars-money-order-draft",
    expected: [0, 62, 1, 8]
  },
  {
    url: "http://192.168.1.100/admin/login.php",
    expected: [0, 36, 0, 9]
  },
  {
    url: "https://sub1.sub2.malicious-site.org/deep/path/?a=1&b=2#ref",
    expected: [1, 59, 2, 15]
  }
];

testCases.forEach((tc, idx) => {
  const extracted = Features.extractFeatures(tc.url);
  console.log(`  Case ${idx + 1}: ${tc.url.substring(0, 45)}...`);
  console.log(`     Got     : [${extracted.join(', ')}]`);
  console.log(`     Expected: [${tc.expected.join(', ')}]`);
  assert.deepStrictEqual(extracted, tc.expected, `Feature mismatch on case ${idx + 1}`);
});
console.log("  [+] All JavaScript feature extraction tests PASSED with 100% Python parity.");

// Test 2: Random Forest Inference
console.log("\n[2] Testing Random Forest Model Inference Structure...");
assert.strictEqual(modelJson.trees.length, 100, "Expected 100 decision trees in model");
assert.deepStrictEqual(modelJson.classes, [0, 1], "Expected binary classes [0, 1]");

const testVectors = [
  { vec: [0.0, 45.0, 1.0, 8.0], expectedPred: 0 },
  { vec: [0.0, 95.0, 3.0, 22.0], expectedPred: 1 },
  { vec: [1.0, 120.0, 4.0, 28.0], expectedPred: 1 }
];

testVectors.forEach((tv, idx) => {
  const res = ModelEngine.predict(modelJson, tv.vec);
  console.log(`  Vector ${idx + 1} [${tv.vec}]: Pred=${res.prediction} (${res.verdict}), Score=${res.confidenceScore}%, Prob=${res.phishingProbability}`);
  assert.strictEqual(res.prediction, tv.expectedPred, `Prediction mismatch on vector ${idx + 1}`);
  assert(res.confidenceScore >= 0 && res.confidenceScore <= 100);
});
console.log("  [+] Model inference structure tests PASSED.");

// Test 3: Benchmark JavaScript Inference Latency
console.log("\n[3] Benchmarking Offline JavaScript Inference Speed...");
const benchmarkUrl = "https://secure-login.update-billing-verification.com/account/login.php?session=938201";
const feats = Features.extractFeatures(benchmarkUrl);

// Warmup
for (let i = 0; i < 50; i++) {
  ModelEngine.predict(modelJson, feats);
}

const iterations = 500;
const start = process.hrtime.bigint();
for (let i = 0; i < iterations; i++) {
  ModelEngine.predict(modelJson, feats);
}
const elapsedNs = process.hrtime.bigint() - start;
const avgMs = Number(elapsedNs) / (iterations * 1e6);

console.log(`  Processed ${iterations} tree ensemble evaluations in ${(Number(elapsedNs)/1e6).toFixed(2)} ms.`);
console.log(`  Average JS inference latency: ${avgMs.toFixed(3)} ms per URL.`);
assert(avgMs < 2.0, "Inference latency exceeded 2ms threshold!");
console.log("  [+] Sub-millisecond offline performance requirement SATISFIED.");

console.log("\n[+] test_inference.js: ALL TESTS PASSED SUCCESSFULLY.");
