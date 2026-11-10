/**
 * random_forest_predict.js - Offline Random Forest Inference Engine for PhishXcape
 * 
 * Executes scikit-learn exported decision trees inside the Chrome Extension:
 * - 100% offline, zero external dependencies, zero latency.
 * - Ensembles 100 trees to calculate average phishing probability.
 * - Returns classification result and transparent model score.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishXcapeModel = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Traverses a single serialized decision tree.
   * @param {Object} tree - Serialized tree node arrays
   * @param {Array<number>} features - [https_present, url_length, subdomain_count, special_char_count]
   * @returns {number} Phishing probability from this tree leaf
   */
  function evaluateTree(tree, features) {
    let node = 0;
    const { left, right, feature, threshold, phish_prob } = tree;

    // Traverse until leaf node (feature === -2)
    while (feature[node] !== -2 && feature[node] !== undefined) {
      const featIdx = feature[node];
      const thresh = threshold[node];
      const val = features[featIdx];

      if (val <= thresh) {
        node = left[node];
      } else {
        node = right[node];
      }
    }

    return phish_prob[node] !== undefined ? phish_prob[node] : 0.5;
  }

  /**
   * Performs ensemble inference over all trees in the exported model.
   * 
   * @param {Object} modelJson - Parsed JSON object of random_forest_model.json
   * @param {Array<number>} features - Feature array
   * @param {number} threshold - Decision threshold (default: 0.50)
   * @returns {Object} Prediction details
   */
  function predict(modelJson, features, threshold = 0.50) {
    if (!modelJson || !Array.isArray(modelJson.trees) || modelJson.trees.length === 0) {
      throw new Error("Invalid model format or empty trees array.");
    }

    const nTrees = modelJson.trees.length;
    let sumProb = 0;

    for (let i = 0; i < nTrees; i++) {
      sumProb += evaluateTree(modelJson.trees[i], features);
    }

    const avgProb = sumProb / nTrees;
    const prediction = avgProb >= threshold ? 1 : 0;
    
    // Model score represents ensemble tree voting consensus
    // (Documented as model score, not calibrated real-world Bayesian probability)
    const confidencePct = Math.round((prediction === 1 ? avgProb : (1 - avgProb)) * 100);

    return {
      prediction: prediction, // 0 = Legitimate, 1 = Phishing
      verdict: prediction === 1 ? "PHISHING" : "LEGITIMATE",
      phishingProbability: Number(avgProb.toFixed(4)),
      confidenceScore: confidencePct,
      featureValues: features,
      treeCount: nTrees
    };
  }

  return {
    evaluateTree,
    predict
  };
}));
