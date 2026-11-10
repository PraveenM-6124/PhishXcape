/**
 * feature_extraction.js - JavaScript Feature Extraction for PhishXcape
 * 
 * Implements the 4 URL security features in JavaScript:
 * 1. HTTPS Presence (1 if https:// or https:, 0 otherwise)
 * 2. URL Length (string length)
 * 3. Subdomain Count (multi-level suffix aware)
 * 4. Special Character Count (matches documented character set)
 * 
 * Works in both browser extensions (Service Worker / Popup) and Node.js environments.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishXcapeFeatures = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Documented fixed set of special characters for parity across Python & JavaScript
  const SPECIAL_CHARACTERS = new Set([
    '-', '.', '_', '~', ':', '/', '?', '#', '[', ']', '@',
    '!', '$', '&', "'", '(', ')', '*', '+', ',', ';', '%',
    '=', '\\', '^', '|', '{', '}', ' ', '`', '"', '<', '>'
  ]);

  // Precompiled multi-part public suffixes
  const MULTI_PART_SUFFIXES = new Set([
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
  ]);

  const FEATURE_NAMES = [
    'https_present',
    'url_length',
    'subdomain_count',
    'special_char_count'
  ];

  /**
   * Evaluates HTTPS presence.
   * Returns 1 if URL explicitly uses HTTPS, 0 otherwise.
   */
  function checkHttps(url) {
    if (!url || typeof url !== 'string') return 0;
    const cleaned = url.trim().toLowerCase();
    if (cleaned.startsWith('https://') || cleaned.startsWith('https:')) {
      return 1;
    }
    return 0;
  }

  /**
   * Returns URL length.
   */
  function getUrlLength(url) {
    if (!url || typeof url !== 'string') return 0;
    return url.trim().length;
  }

  /**
   * Counts subdomain tokens preceding the registrable domain.
   */
  function countSubdomains(url) {
    if (!url || typeof url !== 'string') return 0;
    let u = url.trim().toLowerCase();

    // Strip scheme if present
    if (u.includes('://')) {
      u = u.split('://')[1];
    }

    // Isolate hostname
    let host = u.split('/')[0].split('?')[0].split('#')[0];
    if (host.includes('@')) {
      host = host.split('@').pop();
    }
    if (host.includes(':')) {
      host = host.split(':')[0];
    }

    // Clean edge dots
    host = host.replace(/^\.+|\.+$/g, '');
    if (!host) return 0;

    // IPv4 address check
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      return 0;
    }

    const parts = host.split('.');
    if (parts.length <= 1) {
      return 0;
    }

    let suffixLen = 1;
    if (parts.length >= 3) {
      const twoPartTld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
      if (MULTI_PART_SUFFIXES.has(twoPartTld)) {
        suffixLen = 2;
      }
    }

    const subdomains = parts.length - 1 - suffixLen;
    return Math.max(0, subdomains);
  }

  /**
   * Counts occurrences of documented URL special characters.
   */
  function countSpecialCharacters(url) {
    if (!url || typeof url !== 'string') return 0;
    let count = 0;
    for (let i = 0; i < url.length; i++) {
      if (SPECIAL_CHARACTERS.has(url[i])) {
        count++;
      }
    }
    return count;
  }

  /**
   * Extracts the 4 standardized features as an array:
   * [https_present, url_length, subdomain_count, special_char_count]
   */
  function extractFeatures(url) {
    return [
      checkHttps(url),
      getUrlLength(url),
      countSubdomains(url),
      countSpecialCharacters(url)
    ];
  }

  /**
   * Extracts features as a dictionary.
   */
  function extractFeaturesDict(url) {
    const arr = extractFeatures(url);
    return {
      https_present: arr[0],
      url_length: arr[1],
      subdomain_count: arr[2],
      special_char_count: arr[3]
    };
  }

  return {
    FEATURE_NAMES,
    checkHttps,
    getUrlLength,
    countSubdomains,
    countSpecialCharacters,
    extractFeatures,
    extractFeaturesDict
  };
}));
