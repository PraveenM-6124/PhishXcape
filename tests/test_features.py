"""
test_features.py - Unit Tests for Python Feature Extraction in PhishXcape

Validates:
1. HTTPS Presence detection (explicit https vs scheme-less vs http)
2. URL Length measurement
3. Subdomain counting (public suffix handling, IP addresses, multiple dots)
4. Special character counting against documented character set
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "model"))
from feature_extraction import (
    check_https, get_url_length, count_subdomains,
    count_special_characters, extract_features, extract_features_dict,
    SPECIAL_CHARACTERS
)

class TestFeatureExtraction(unittest.TestCase):

    def test_https_presence(self):
        # Explicit HTTPS
        self.assertEqual(check_https("https://secure.bank.com"), 1)
        self.assertEqual(check_https("HTTPS://LOGIN.PAYPAL.COM"), 1)
        self.assertEqual(check_https("https://site.org/path?q=1"), 1)

        # Insecure or non-HTTPS
        self.assertEqual(check_https("http://insecure.bank.com"), 0)
        self.assertEqual(check_https("ftp://files.org"), 0)

        # Scheme-less URLs (documented specification for urlset.csv)
        self.assertEqual(check_https("bank.com/login"), 0)
        self.assertEqual(check_https("www.paypal.com"), 0)
        self.assertEqual(check_https(""), 0)

    def test_url_length(self):
        self.assertEqual(get_url_length("http://abc.com"), 14)
        self.assertEqual(get_url_length("  https://test.org  "), 16)
        self.assertEqual(get_url_length(""), 0)

    def test_subdomain_count(self):
        # Single domain without subdomains
        self.assertEqual(count_subdomains("example.com"), 0)
        self.assertEqual(count_subdomains("https://example.com/test"), 0)
        
        # Standard subdomain
        self.assertEqual(count_subdomains("login.example.com"), 1)
        self.assertEqual(count_subdomains("www.google.com"), 1)
        
        # Multi-level subdomains
        self.assertEqual(count_subdomains("a.b.c.example.com"), 3)
        self.assertEqual(count_subdomains("https://secure.pay.paypal.com/auth"), 2)

        # Multi-part public suffixes (.co.uk, .com.au)
        self.assertEqual(count_subdomains("bank.co.uk"), 0)
        self.assertEqual(count_subdomains("login.bank.co.uk"), 1)
        self.assertEqual(count_subdomains("https://auth.sub.bank.com.au/login"), 2)

        # IP address host (no subdomains)
        self.assertEqual(count_subdomains("http://192.168.1.1/admin"), 0)
        self.assertEqual(count_subdomains("10.0.0.1"), 0)

        # Empty / edge cases
        self.assertEqual(count_subdomains(""), 0)
        self.assertEqual(count_subdomains("localhost"), 0)

    def test_special_characters(self):
        # Documented set test
        url = "https://bank.com/login.php?user=admin&token=123#ref"
        # special chars: ':', '/', '/', '.', '/', '.', '?', '=', '&', '=', '#' -> 11 chars
        self.assertEqual(count_special_characters(url), 11)

        # Alphanumeric only
        self.assertEqual(count_special_characters("abcdef12345"), 0)

        # All documented special chars should be counted
        sample_chars = "-._~:/?#[]@!$&'()*+,;%=\\^|{} `\"<>"
        self.assertEqual(count_special_characters(sample_chars), len(sample_chars))

    def test_extract_features_shape_and_keys(self):
        url = "https://sub.portal.bank.co.uk/verify?id=99&auth=yes"
        feats = extract_features(url)
        self.assertEqual(len(feats), 4)
        self.assertIsInstance(feats[0], int)
        self.assertIsInstance(feats[1], int)
        self.assertIsInstance(feats[2], int)
        self.assertIsInstance(feats[3], int)

        dict_feats = extract_features_dict(url)
        expected_keys = {'https_present', 'url_length', 'subdomain_count', 'special_char_count'}
        self.assertEqual(set(dict_feats.keys()), expected_keys)

if __name__ == "__main__":
    unittest.main()
