"""
select_samples.py - Balanced Dataset Selection for PhishXcape

Reads data/urlset.csv:
1. Cleans missing, null, or non-numeric labels.
2. Removes duplicate URLs.
3. Filters for well-formed URL strings.
4. Samples exactly 5,000 legitimate (label=0) and 5,000 phishing (label=1) records.
5. Shuffles using random_state=42 for deterministic reproducibility.
6. Saves to model/phishing_urls.csv with columns: 'url', 'label'.
"""

import os
import sys
import pandas as pd
import numpy as np

# Ensure Windows terminal handles UTF-8 characters safely
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

INPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "urlset.csv")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "phishing_urls.csv")

def select_and_balance_dataset(input_path, output_path, samples_per_class=5000, random_state=42):
    print("=" * 60)
    print("PHISHXCAPE DATASET PREPARATION & BALANCED SAMPLING")
    print("=" * 60)
    
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input dataset not found at {input_path}")
        
    print(f"Loading raw dataset from: {input_path}")
    df = pd.read_csv(input_path, encoding='latin-1', on_bad_lines='skip', low_memory=False)
    print(f"Initial raw parsed rows: {len(df):,}")
    
    # Identify domain and label columns
    domain_col = 'domain'
    label_col = 'label'
    
    # 1. Drop rows with null domain or label
    df_clean = df[[domain_col, label_col]].dropna().copy()
    
    # 2. Rename domain to url
    df_clean.rename(columns={domain_col: 'url'}, inplace=True)
    
    # 3. Ensure url is string and strip whitespace
    df_clean['url'] = df_clean['url'].astype(str).str.strip()
    df_clean = df_clean[df_clean['url'].str.len() > 0]
    
    # 4. Clean labels: convert to integer 0 or 1
    df_clean['label'] = pd.to_numeric(df_clean['label'], errors='coerce')
    df_clean = df_clean[df_clean['label'].isin([0, 1])].copy()
    df_clean['label'] = df_clean['label'].astype(int)
    
    # 5. Remove duplicate URLs
    before_dedup = len(df_clean)
    df_clean.drop_duplicates(subset=['url'], inplace=True)
    print(f"Rows after dropping duplicates & invalid entries: {len(df_clean):,} (dropped {before_dedup - len(df_clean)} duplicates)")
    
    # 6. Check counts per class
    legit_df = df_clean[df_clean['label'] == 0]
    phish_df = df_clean[df_clean['label'] == 1]
    
    print(f"Available Legitimate (0): {len(legit_df):,}")
    print(f"Available Phishing   (1): {len(phish_df):,}")
    
    if len(legit_df) < samples_per_class or len(phish_df) < samples_per_class:
        raise ValueError(f"Insufficient samples to select {samples_per_class} per class!")
        
    # 7. Sample exactly samples_per_class with fixed seed
    sampled_legit = legit_df.sample(n=samples_per_class, random_state=random_state)
    sampled_phish = phish_df.sample(n=samples_per_class, random_state=random_state)
    
    # 8. Combine and shuffle
    balanced_df = pd.concat([sampled_legit, sampled_phish], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    
    # 9. Validation
    assert len(balanced_df) == samples_per_class * 2, f"Expected {samples_per_class * 2} rows, got {len(balanced_df)}"
    assert (balanced_df['label'] == 0).sum() == samples_per_class
    assert (balanced_df['label'] == 1).sum() == samples_per_class
    assert balanced_df['url'].isnull().sum() == 0
    assert balanced_df.duplicated(subset=['url']).sum() == 0
    
    # 10. Save to CSV
    balanced_df.to_csv(output_path, index=False, encoding='utf-8')
    print(f"\n[+] Successfully saved {len(balanced_df):,} balanced samples to:")
    print(f"    {output_path}")
    print(f"    - Legitimate (0): {(balanced_df['label'] == 0).sum():,}")
    print(f"    - Phishing   (1): {(balanced_df['label'] == 1).sum():,}")
    print("=" * 60)
    
    print("\nSample records:")
    print(balanced_df.head(10))
    return balanced_df

if __name__ == "__main__":
    select_and_balance_dataset(INPUT_PATH, OUTPUT_PATH)
