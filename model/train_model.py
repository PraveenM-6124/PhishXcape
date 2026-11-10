"""
train_model.py - Model Training & Evaluation for PhishXcape

Trains a RandomForestClassifier using the 4 URL security features:
1. https_present
2. url_length
3. subdomain_count
4. special_char_count

Pipeline:
- Loads balanced 10,000 sample dataset (model/phishing_urls.csv)
- Extracts the 4 URL features
- Stratified 80/20 train/test split (8,000 train / 2,000 test)
- Trains scikit-learn RandomForestClassifier
- Evaluates Accuracy, Precision, Recall, F1-score, and Confusion Matrix
- Serializes trained model to model/random_forest.pkl
- Generates performance visualizations in Output/ directory
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg') # Headless rendering for automated environments
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# Ensure Windows terminal handles UTF-8 characters safely
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Import feature extraction logic
from feature_extraction import extract_features, FEATURE_NAMES

DATA_PATH = os.path.join(os.path.dirname(__file__), "phishing_urls.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "random_forest.pkl")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "Output")

# Ensure Output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Styling palette for cybersecurity charts (Red, Black, Dark Gray, White)
BG_COLOR = "#0B0B0F"
CARD_COLOR = "#1C1C24"
TEXT_COLOR = "#FFFFFF"
MUTED_TEXT = "#A1A1AA"
RED_PRIMARY = "#E50914"
RED_DARK = "#B20710"
GRID_COLOR = "#33333D"

def plot_accuracy_metrics(accuracy, precision, recall, f1, output_path):
    """Generates a bar chart comparing core performance metrics."""
    fig, ax = plt.subplots(figsize=(8, 5), facecolor=BG_COLOR)
    ax.set_facecolor(CARD_COLOR)
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    values = [accuracy * 100, precision * 100, recall * 100, f1 * 100]
    colors = [RED_PRIMARY, '#FF4B4B', '#D1001F', RED_DARK]
    
    bars = ax.bar(metrics, values, color=colors, width=0.55, edgecolor='#FFFFFF', linewidth=1.2, zorder=3)
    ax.set_ylim(0, 105)
    ax.grid(axis='y', linestyle='--', alpha=0.3, color=GRID_COLOR, zorder=0)
    
    # Value annotations on top of bars
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.2f}%",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 6),
                    textcoords="offset points",
                    ha='center', va='bottom',
                    color=TEXT_COLOR, fontsize=12, fontweight='bold')
                    
    ax.set_title("PhishXcape - Model Evaluation Metrics (2,000 Test Samples)",
                 color=TEXT_COLOR, fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel("Score (%)", color=TEXT_COLOR, fontsize=12)
    ax.tick_params(colors=MUTED_TEXT, labelsize=11)
    
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
        
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved Accuracy Chart to: {output_path}")

def plot_confusion_matrix(cm, output_path):
    """Generates a styled confusion matrix heatmap."""
    fig, ax = plt.subplots(figsize=(6, 5), facecolor=BG_COLOR)
    ax.set_facecolor(CARD_COLOR)
    
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Reds)
    cbar = ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.ax.tick_params(colors=MUTED_TEXT, labelsize=10)
    cbar.outline.set_edgecolor(GRID_COLOR)
    
    classes = ['Legitimate (0)', 'Phishing (1)']
    tick_marks = np.arange(len(classes))
    ax.set_xticks(tick_marks)
    ax.set_yticks(tick_marks)
    ax.set_xticklabels(classes, color=TEXT_COLOR, fontsize=11)
    ax.set_yticklabels(classes, color=TEXT_COLOR, fontsize=11)
    
    # Annotate numbers
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            label_text = f"{val:,}"
            if i == 0 and j == 0:
                sub = "\n(True Neg)"
            elif i == 0 and j == 1:
                sub = "\n(False Pos)"
            elif i == 1 and j == 0:
                sub = "\n(False Neg)"
            else:
                sub = "\n(True Pos)"
                
            ax.text(j, i, label_text + sub,
                    ha="center", va="center",
                    color="white" if val > thresh else "#0B0B0F",
                    fontsize=11, fontweight='bold')
                    
    ax.set_title("PhishXcape - Confusion Matrix", color=TEXT_COLOR, fontsize=13, fontweight='bold', pad=15)
    ax.set_ylabel("True Label", color=TEXT_COLOR, fontsize=12)
    ax.set_xlabel("Predicted Label", color=TEXT_COLOR, fontsize=12)
    
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
        
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved Confusion Matrix to: {output_path}")

def plot_feature_importance(importances, feature_names, output_path):
    """Generates a horizontal feature importance chart."""
    fig, ax = plt.subplots(figsize=(8, 4.5), facecolor=BG_COLOR)
    ax.set_facecolor(CARD_COLOR)
    
    indices = np.argsort(importances)
    sorted_features = [feature_names[i] for i in indices]
    sorted_importances = importances[indices] * 100
    
    bars = ax.barh(sorted_features, sorted_importances, color=RED_PRIMARY, edgecolor='#FFFFFF', height=0.55, zorder=3)
    ax.grid(axis='x', linestyle='--', alpha=0.3, color=GRID_COLOR, zorder=0)
    
    for bar in bars:
        w = bar.get_width()
        ax.annotate(f"{w:.2f}%",
                    xy=(w, bar.get_y() + bar.get_height() / 2),
                    xytext=(6, 0),
                    textcoords="offset points",
                    ha='left', va='center',
                    color=TEXT_COLOR, fontsize=11, fontweight='bold')
                    
    ax.set_title("PhishXcape - Random Forest Feature Importance",
                 color=TEXT_COLOR, fontsize=13, fontweight='bold', pad=15)
    ax.set_xlabel("Relative Importance (%)", color=TEXT_COLOR, fontsize=11)
    ax.tick_params(colors=MUTED_TEXT, labelsize=11)
    
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
        
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved Feature Importance Chart to: {output_path}")

def train_phishxcape_model():
    print("=" * 65)
    print("PHISHXCAPE - RANDOM FOREST MODEL TRAINING & EVALUATION")
    print("=" * 65)
    
    # 1. Load balanced dataset
    print(f"\n1. Loading balanced dataset from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    print(f"   Loaded {len(df):,} records.")
    print(f"   Class distribution: Legitimate (0) = {(df['label'] == 0).sum():,}, Phishing (1) = {(df['label'] == 1).sum():,}")
    
    # 2. Extract 4 URL features
    print("\n2. Extracting 4 URL features...")
    feature_matrix = []
    for u in df['url']:
        feature_matrix.append(extract_features(u))
        
    X = np.array(feature_matrix, dtype=np.float32)
    y = df['label'].values.astype(int)
    
    print(f"   Feature matrix shape: {X.shape} (Features: {FEATURE_NAMES})")
    
    # 3. Stratified Train/Test split (80:20 -> 8,000 train, 2,000 test)
    print("\n3. Performing 80:20 stratified train/test split...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"   Training samples : {len(y_train):,} (Legit: {(y_train == 0).sum()}, Phish: {(y_train == 1).sum()})")
    print(f"   Testing samples  : {len(y_test):,}  (Legit: {(y_test == 0).sum()}, Phish: {(y_test == 1).sum()})")
    
    # 4. Initialize and train Random Forest Classifier
    # Hyperparameters:
    # - n_estimators=100: Standard robust ensemble size for low variance
    # - max_depth=12: Pruning depth to prevent overfitting on specific length thresholds and keep exported JS model lightweight (~50-100KB)
    # - min_samples_split=5: Regularization against noisy samples
    # - random_state=42: Deterministic reproducibility
    # - n_jobs=-1: Multi-threaded execution
    print("\n4. Training RandomForestClassifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    print("   [+] Training complete.")
    
    # 5. Evaluate on Test Set
    print("\n5. Evaluating model performance on test set (2,000 samples)...")
    y_pred = rf_model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print("-" * 65)
    print("MODEL PERFORMANCE RESULTS:")
    print(f"   * Accuracy : {acc * 100:.2f}%")
    print(f"   * Precision: {prec * 100:.2f}%")
    print(f"   * Recall   : {rec * 100:.2f}%")
    print(f"   * F1-Score : {f1 * 100:.2f}%")
    print("-" * 65)
    print("Confusion Matrix:")
    print(cm)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)']))
    
    # Feature Importances
    print("Feature Importances:")
    for name, imp in zip(FEATURE_NAMES, rf_model.feature_importances_):
        print(f"   - {name:20}: {imp * 100:.2f}%")
        
    # 6. Save serialized model
    joblib.dump(rf_model, MODEL_OUTPUT_PATH)
    print(f"\n[+] Saved trained model to: {MODEL_OUTPUT_PATH}")
    
    # 7. Generate Visualizations
    print("\n6. Generating Visualizations...")
    plot_accuracy_metrics(acc, prec, rec, f1, os.path.join(OUTPUT_DIR, "accuracy_chart.png"))
    plot_confusion_matrix(cm, os.path.join(OUTPUT_DIR, "confusion_matrix.png"))
    plot_feature_importance(rf_model.feature_importances_, FEATURE_NAMES, os.path.join(OUTPUT_DIR, "feature_importance.png"))
    
    print("\n[+] Stage 4 & 5 Completed Successfully.")
    return rf_model, acc, prec, rec, f1, cm

if __name__ == "__main__":
    train_phishxcape_model()
