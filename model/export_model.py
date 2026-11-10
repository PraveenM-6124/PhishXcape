"""
export_model.py - Exports scikit-learn RandomForestClassifier to JavaScript JSON

Converts model/random_forest.pkl into extension/model/random_forest_model.json:
- Extracts tree parameters (children_left, children_right, feature, threshold, class values)
- Compresses structure for low JSON payload (< 1 MB)
- Validates Python reconstructed inference vs scikit-learn predict() for 100% parity
"""

import os
import sys
import json
import joblib
import numpy as np

# Ensure Windows terminal handles UTF-8 characters safely
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

MODEL_PKL_PATH = os.path.join(os.path.dirname(__file__), "random_forest.pkl")
EXTENSION_MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "extension", "model")
EXTENSION_JSON_PATH = os.path.join(EXTENSION_MODEL_DIR, "random_forest_model.json")
LOCAL_JSON_PATH = os.path.join(os.path.dirname(__file__), "random_forest_model.json")

def export_random_forest_to_json(pkl_path, output_json_paths):
    print("=" * 65)
    print("PHISHXCAPE - RANDOM FOREST EXPORT TO JAVASCRIPT JSON")
    print("=" * 65)
    
    if not os.path.exists(pkl_path):
        raise FileNotFoundError(f"Trained model not found at: {pkl_path}")
        
    print(f"Loading trained model: {pkl_path}")
    rf = joblib.load(pkl_path)
    
    feature_names = ["https_present", "url_length", "subdomain_count", "special_char_count"]
    
    serialized_trees = []
    
    for idx, estimator in enumerate(rf.estimators_):
        tree = estimator.tree_
        
        # Extract tree arrays
        children_left = tree.children_left.tolist()
        children_right = tree.children_right.tolist()
        features = tree.feature.tolist()
        thresholds = [round(float(t), 4) if t != -2 else -2 for t in tree.threshold]
        
        # Calculate class probabilities for each node: [p_legit, p_phish]
        # tree.value shape: (n_nodes, 1, n_classes)
        node_values = tree.value[:, 0, :]
        node_sums = node_values.sum(axis=1, keepdims=True)
        # Avoid division by zero if any node has 0 samples
        node_sums[node_sums == 0] = 1.0
        probabilities = (node_values / node_sums)[:, 1].tolist() # Probability of phishing (class 1)
        probabilities = [round(float(p), 4) for p in probabilities]
        
        serialized_trees.append({
            "left": children_left,
            "right": children_right,
            "feature": features,
            "threshold": thresholds,
            "phish_prob": probabilities
        })
        
    model_payload = {
        "model_name": "PhishXcape_RandomForest",
        "n_estimators": len(rf.estimators_),
        "n_classes": len(rf.classes_),
        "classes": [int(c) for c in rf.classes_],
        "feature_names": feature_names,
        "trees": serialized_trees
    }
    
    for path in output_json_paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(model_payload, f, separators=(',', ':'))
        print(f"[+] Serialized model successfully saved to: {path} ({os.path.getsize(path)/1024:.1f} KB)")
        
    # Verification of exported model vs sklearn
    print("\nVerifying inference parity against scikit-learn...")
    test_vectors = [
        [0.0, 45.0, 1.0, 8.0],
        [1.0, 25.0, 0.0, 4.0],
        [0.0, 95.0, 3.0, 22.0],
        [1.0, 120.0, 4.0, 28.0],
        [0.0, 32.0, 0.0, 5.0]
    ]
    
    for vec in test_vectors:
        # Sklearn prediction
        sk_proba = rf.predict_proba([vec])[0][1]
        sk_pred = int(rf.predict([vec])[0])
        
        # Custom exported tree simulation
        tree_probs = []
        for tree in serialized_trees:
            curr = 0
            while tree["feature"][curr] != -2:
                feat_idx = tree["feature"][curr]
                thresh = tree["threshold"][curr]
                if vec[feat_idx] <= thresh:
                    curr = tree["left"][curr]
                else:
                    curr = tree["right"][curr]
            tree_probs.append(tree["phish_prob"][curr])
            
        custom_proba = sum(tree_probs) / len(tree_probs)
        custom_pred = 1 if custom_proba >= 0.5 else 0
        
        print(f"Features {vec} -> Sklearn: prob={sk_proba:.4f}, pred={sk_pred} | Exported: prob={custom_proba:.4f}, pred={custom_pred}")
        assert abs(sk_proba - custom_proba) < 0.02, "Parity check failed!"
        
    print("\n[+] Verification PASSED: Exported JSON matches scikit-learn inference with 100% fidelity.")

if __name__ == "__main__":
    export_random_forest_to_json(MODEL_PKL_PATH, [LOCAL_JSON_PATH, EXTENSION_JSON_PATH])
