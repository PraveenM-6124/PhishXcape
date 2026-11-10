"""
inspect_dataset.py - Dataset Verification and Inspection for PhishXcape

Analyzes urlset.csv:
- Checks file encoding compatibility
- Captures and logs malformed lines with reason
- Analyzes columns, data types, missing values, duplicates, and label distribution
"""

import os
import sys
import csv
import pandas as pd
import numpy as np

# Ensure Windows terminal handles UTF-8 characters safely
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "urlset.csv")

def detect_encoding(file_path):
    # As noted in project requirements, urlset.csv contains non-UTF8 binary-like tokens in raw URLs.
    # latin-1 (ISO-8859-1) maps all byte values 0x00-0xFF, avoiding decode errors.
    print("[+] Using 'latin-1' encoding for robust decoding across all byte ranges.")
    return 'latin-1'

def inspect_raw_file(file_path, encoding):
    print("\n" + "="*60)
    print("STEP 1: RAW LINE INSPECTION & MALFORMED ROW AUDIT")
    print("="*60)
    
    total_raw_lines = 0
    malformed_rows = []
    expected_col_count = 14
    
    with open(file_path, 'r', encoding=encoding, errors='replace') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
            expected_col_count = len(header)
            print(f"Header fields ({expected_col_count}): {header}")
        except Exception as e:
            print(f"Error reading header: {e}")
            return
            
        for idx, row in enumerate(reader, start=2):
            total_raw_lines += 1
            if len(row) != expected_col_count:
                malformed_rows.append({
                    'line_number': idx,
                    'col_count': len(row),
                    'sample_data': row[:3] if len(row) >= 3 else row,
                    'reason': f"Expected {expected_col_count} columns, got {len(row)}"
                })

    print(f"Total data rows in file: {total_raw_lines:,}")
    print(f"Malformed rows detected: {len(malformed_rows):,}")
    if malformed_rows:
        print("Sample malformed rows:")
        for r in malformed_rows[:5]:
            print(f"  Line {r['line_number']}: {r['reason']} | Content preview: {r['sample_data']}")
    return expected_col_count

def inspect_with_pandas(file_path, encoding):
    print("\n" + "="*60)
    print("STEP 2: PANDAS DATASET STRUCTURE & LABEL ANALYSIS")
    print("="*60)
    
    # Using on_bad_lines='skip' to parse successfully while keeping count
    df = pd.read_csv(file_path, encoding=encoding, on_bad_lines='skip', low_memory=False)
    
    print(f"Successfully loaded DataFrame shape: {df.shape[0]:,} rows x {df.shape[1]} columns")
    print("\nColumns detected:")
    for c in df.columns:
        print(f" - {c} ({df[c].dtype})")
        
    print("\nMissing values per column:")
    null_counts = df.isnull().sum()
    print(null_counts[null_counts > 0])
    
    # Check domain column
    domain_col = 'domain' if 'domain' in df.columns else df.columns[0]
    label_col = 'label' if 'label' in df.columns else df.columns[-1]
    
    print(f"\nTarget columns: Domain='{domain_col}', Label='{label_col}'")
    
    # Duplicates in domain
    num_domain_duplicates = df.duplicated(subset=[domain_col]).sum()
    print(f"Duplicate domain entries: {num_domain_duplicates:,}")
    
    # Value counts of label
    print("\nRaw label distribution:")
    print(df[label_col].value_counts(dropna=False))
    
    # Convert label to numeric and check valid 0 and 1
    numeric_labels = pd.to_numeric(df[label_col], errors='coerce')
    valid_mask = numeric_labels.isin([0, 1]) & df[domain_col].notnull()
    
    clean_legit = (numeric_labels[valid_mask] == 0).sum()
    clean_phish = (numeric_labels[valid_mask] == 1).sum()
    invalid_labels = len(df) - valid_mask.sum()
    
    print("\nValidated label distribution (0=Legitimate, 1=Phishing):")
    print(f" - Legitimate (0): {clean_legit:,}")
    print(f" - Phishing   (1): {clean_phish:,}")
    print(f" - Missing/Invalid labels or domains: {invalid_labels:,}")
    
    return df

def main():
    if not os.path.exists(DATA_PATH):
        print(f"[!] Dataset not found at: {DATA_PATH}")
        sys.exit(1)
        
    encoding = detect_encoding(DATA_PATH)
    inspect_raw_file(DATA_PATH, encoding)
    inspect_with_pandas(DATA_PATH, encoding)

if __name__ == "__main__":
    main()
