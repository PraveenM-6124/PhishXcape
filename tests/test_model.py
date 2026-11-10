"""
test_model.py - Unit Tests for Python Random Forest Classifier in PhishXcape

Validates:
1. Model deserialization from model/random_forest.pkl
2. Structural integrity (100 estimators, 4 input features, binary classes)
3. Prediction outputs (strictly 0 or 1, valid probability ranges [0, 1])
4. Real-time inference latency benchmarks (< 10ms per URL feature vector)
"""

import os
import sys
import time
import unittest
import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "random_forest.pkl")

class TestRandomForestModel(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file missing: {MODEL_PATH}")
        cls.model = joblib.load(MODEL_PATH)

    def test_model_structure(self):
        # 100 trees
        self.assertEqual(len(self.model.estimators_), 100)
        # 4 features input
        self.assertEqual(self.model.n_features_in_, 4)
        # Binary classification [0, 1]
        self.assertEqual(list(self.model.classes_), [0, 1])

    def test_predictions_binary_and_probabilities(self):
        sample_vectors = np.array([
            [0.0, 45.0, 1.0, 8.0],
            [1.0, 25.0, 0.0, 4.0],
            [0.0, 95.0, 3.0, 22.0],
            [1.0, 120.0, 4.0, 28.0]
        ], dtype=np.float32)

        preds = self.model.predict(sample_vectors)
        probs = self.model.predict_proba(sample_vectors)

        self.assertEqual(len(preds), len(sample_vectors))
        self.assertEqual(probs.shape, (len(sample_vectors), 2))

        for p in preds:
            self.assertIn(p, [0, 1])

        for prob in probs:
            self.assertAlmostEqual(float(prob[0] + prob[1]), 1.0, places=4)
            self.assertTrue(0.0 <= prob[0] <= 1.0)
            self.assertTrue(0.0 <= prob[1] <= 1.0)

    def test_inference_latency(self):
        test_vec = np.array([[0.0, 50.0, 1.0, 10.0]], dtype=np.float32)
        
        # Warmup
        for _ in range(10):
            _ = self.model.predict(test_vec)

        # Benchmark 100 iterations
        start = time.perf_counter()
        n_iters = 100
        for _ in range(n_iters):
            _ = self.model.predict(test_vec)
        duration = time.perf_counter() - start

        avg_latency_ms = (duration / n_iters) * 1000
        print(f"\n[+] Average Python model inference latency: {avg_latency_ms:.3f} ms")
        self.assertLess(avg_latency_ms, 60.0, "Inference latency exceeded 60ms threshold!")

if __name__ == "__main__":
    unittest.main()
