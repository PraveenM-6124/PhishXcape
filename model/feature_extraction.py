r"""
feature_extraction.py - URL Feature Extractor for PhishXcape

Implements the four foundational URL security features:
1. HTTPS Presence:
   - Evaluates whether the URL explicitly uses HTTPS (starts with 'https://' or 'https:').
   - Evaluates to 1 for HTTPS and 0 for non-HTTPS (e.g., http://, ftp://, or scheme-less strings).
   - Limitation note: In offline datasets like urlset.csv, raw URLs frequently omit the scheme
     (e.g., 'domain.com/path'). As mandated, we never invent missing schemes; scheme-less records
     receive 0 (unverified scheme). During real-time browser extension monitoring, window.location.href
     provides full schemes ('https://...'), correctly receiving 1.

2. URL Length:
   - Measures string length: len(url).
   - Longer URLs frequently conceal obfuscated query parameters and phishing redirect chains.

3. Subdomain Count:
   - Parses the hostname and strips standard multi-part public suffixes (e.g., .co.uk, .com.au).
   - Counts subdomains preceding the registrable domain.
   - Attackers frequently leverage deeply nested subdomains to simulate authentic brand names.

4. Special Character Count:
   - Counts occurrences of designated URL punctuation characters:
     [-._~:/?#[]@!$&'()*+,;%=\^|{} `"<>].
   - Phishing links often contain dense encoding symbols (%, &, =, ?, @) to inject redirection and tracking.
"""

import re
import urllib.parse

# Documented fixed set of special characters for parity across Python & JavaScript
SPECIAL_CHARACTERS = set("-._~:/?#[]@!$&'()*+,;%=\\^|{} `\"<>")

# Precompiled multi-part public suffixes commonly encountered
MULTI_PART_SUFFIXES = {
    'co.uk', 'com.au', 'org.uk', 'co.nz', 'gov.uk', 'ac.uk', 'co.jp', 'com.br',
    'com.mx', 'com.tr', 'com.ar', 'com.pl', 'co.in', 'net.au', 'edu.au', 'gov.in',
    'co.za', 'com.tw', 'com.hk', 'com.sg', 'com.my', 'com.pk', 'com.cn', 'edu.cn',
    'net.cn', 'org.cn', 'gov.cn', 'ac.jp', 'ne.jp', 'or.jp', 'go.jp', 'co.kr',
    'ne.kr', 're.kr', 'pe.kr', 'or.kr', 'go.kr', 'edu.kr', 'ac.in', 'org.in',
    'net.in', 'res.in', 'co.id', 'ac.id', 'or.id', 'go.id', 'web.id', 'sch.id',
    'mil.id', 'co.th', 'ac.th', 'or.th', 'go.th', 'in.th', 'co.il', 'org.il',
    'ac.il', 'gov.il', 'co.at', 'or.at', 'ac.at', 'gv.at', 'co.nz', 'org.nz',
    'net.nz', 'govt.nz', 'ac.nz', 'com.ve', 'org.ve', 'edu.ve', 'gov.ve', 'net.ve',
    'com.do', 'org.do', 'edu.do', 'gov.do', 'net.do', 'com.pe', 'org.pe', 'edu.pe',
    'gob.pe', 'net.pe', 'com.co', 'org.co', 'edu.co', 'gov.co', 'net.co', 'com.ec',
    'com.uy', 'com.py', 'com.bo', 'com.gt', 'com.sv', 'com.hn', 'com.ni', 'com.cr',
    'com.pa', 'com.cu', 'com.pr', 'com.ph', 'org.ph', 'edu.ph', 'gov.ph', 'net.ph',
    'com.vn', 'org.vn', 'edu.vn', 'gov.vn', 'net.vn', 'com.eg', 'edu.eg', 'gov.eg',
    'com.ng', 'edu.ng', 'gov.ng', 'org.ng', 'com.sa', 'edu.sa', 'gov.sa', 'org.sa',
    'com.ua', 'org.ua', 'net.ua', 'edu.ua', 'gov.ua', 'kiev.ua', 'biz.tr', 'gen.tr',
    'info.tr', 'k12.tr', 'name.tr', 'net.tr', 'org.tr', 'web.tr', 'gc.ca', 'on.ca',
    'qc.ca', 'bc.ca', 'ab.ca', 'sk.ca', 'mb.ca', 'ns.ca', 'nb.ca', 'nl.ca', 'pe.ca'
}

FEATURE_NAMES = [
    'https_present',
    'url_length',
    'subdomain_count',
    'special_char_count'
]

def check_https(url: str) -> int:
    """Returns 1 if URL explicitly specifies HTTPS, 0 otherwise."""
    cleaned = url.strip().lower()
    if cleaned.startswith("https://") or cleaned.startswith("https:"):
        return 1
    return 0

def get_url_length(url: str) -> int:
    """Returns string length of the URL."""
    return len(url.strip())

def count_subdomains(url: str) -> int:
    """
    Parses the hostname from the URL, accounts for multi-level public suffixes,
    and returns the count of subdomain labels preceding the registrable domain.
    """
    u = url.strip().lower()
    
    # Strip protocol if present
    if "://" in u:
        host = u.split("://", 1)[1]
    else:
        host = u
        
    # Isolate hostname from paths, queries, credentials, and ports
    host = host.split("/")[0].split("?")[0].split("#")[0]
    if "@" in host:
        host = host.split("@")[-1]
    if ":" in host:
        host = host.split(":")[0]
        
    host = host.strip(".")
    if not host:
        return 0
        
    # Check if host is IPv4 address (e.g., 192.168.1.1)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return 0
        
    parts = host.split(".")
    if len(parts) <= 1:
        return 0
        
    # Check 2-part and 3-part known suffixes
    suffix_len = 1
    if len(parts) >= 3:
        two_part_tld = f"{parts[-2]}.{parts[-1]}"
        if two_part_tld in MULTI_PART_SUFFIXES:
            suffix_len = 2
            
    # Subdomain count = total parts - (domain name + suffix parts)
    subdomains = len(parts) - 1 - suffix_len
    return max(0, subdomains)

def count_special_characters(url: str) -> int:
    """Counts occurrences of documented URL special characters."""
    return sum(1 for ch in url if ch in SPECIAL_CHARACTERS)

def extract_features(url: str) -> list:
    """
    Extracts the four standardized PhishXcape features for a given URL string.
    
    Returns:
        [https_present, url_length, subdomain_count, special_char_count]
    """
    return [
        check_https(url),
        get_url_length(url),
        count_subdomains(url),
        count_special_characters(url)
    ]

def extract_features_dict(url: str) -> dict:
    """Returns the features as a dictionary mapped to canonical feature names."""
    features = extract_features(url)
    return dict(zip(FEATURE_NAMES, features))

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "http://insecure-login.bank.co.uk/verify/index.php?user=1&token=xyz",
        "dniash.solidwebhost.com/louis-daraft-dollars-money-order-draft",
        "http://192.168.1.100/admin/login.php",
        "https://sub1.sub2.malicious-site.org/deep/path/?a=1&b=2#ref"
    ]
    
    print("PHISHXCAPE URL FEATURE EXTRACTION TEST")
    print("=" * 70)
    for u in test_urls:
        feats = extract_features_dict(u)
        print(f"URL: {u}")
        print(f"Features: {feats}\n")
