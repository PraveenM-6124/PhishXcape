/**
 * contentScript.js - Real-Time In-Page Security Alert Injection for PhishXcape
 * 
 * Displays a non-intrusive, prominent cybersecurity alert banner at the top of
 * dangerous phishing or suspicious web pages without harvesting user page content.
 */

(function () {
  'use strict';

  // Listen for alert messages from background service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PHISHXCAPE_ALERT' && message.verdict) {
      injectWarningBanner(message.verdict);
    }
  });

  function injectWarningBanner(verdict) {
    // Avoid duplicate banners
    if (document.getElementById('phishxcape-security-banner')) {
      return;
    }

    const isPhishing = verdict.status === 'PHISHING';
    const banner = document.createElement('div');
    banner.id = 'phishxcape-security-banner';
    
    // Style directly to prevent host site CSS collisions
    banner.style.position = 'fixed';
    banner.style.top = '0';
    banner.style.left = '0';
    banner.style.width = '100%';
    banner.style.zIndex = '2147483647';
    banner.style.backgroundColor = '#0B0B0F';
    banner.style.borderBottom = `3px solid ${isPhishing ? '#E50914' : '#B20710'}`;
    banner.style.boxShadow = '0 6px 20px rgba(0, 0, 0, 0.8)';
    banner.style.color = '#FFFFFF';
    banner.style.fontFamily = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
    banner.style.padding = '14px 24px';
    banner.style.boxSizing = 'border-box';
    banner.style.display = 'flex';
    banner.style.alignItems = 'center';
    banner.style.justifyContent = 'space-between';
    banner.style.transition = 'transform 0.3s ease';

    const leftContainer = document.createElement('div');
    leftContainer.style.display = 'flex';
    leftContainer.style.alignItems = 'center';
    leftContainer.style.gap = '16px';

    const iconBadge = document.createElement('div');
    iconBadge.style.width = '36px';
    iconBadge.style.height = '36px';
    iconBadge.style.borderRadius = '50%';
    iconBadge.style.backgroundColor = isPhishing ? '#E50914' : '#B20710';
    iconBadge.style.display = 'flex';
    iconBadge.style.alignItems = 'center';
    iconBadge.style.justifyContent = 'center';
    iconBadge.style.fontWeight = 'bold';
    iconBadge.style.fontSize = '20px';
    iconBadge.innerText = isPhishing ? '!' : '⚠️';

    const textGroup = document.createElement('div');
    
    const title = document.createElement('div');
    title.style.fontWeight = '700';
    title.style.fontSize = '14px';
    title.style.letterSpacing = '0.5px';
    title.style.color = isPhishing ? '#E50914' : '#FFFFFF';
    title.innerText = `PHISHXCAPE WARNING: ${verdict.headline.toUpperCase()}`;

    const subtitle = document.createElement('div');
    subtitle.style.fontSize = '12px';
    subtitle.style.color = '#A1A1AA';
    subtitle.style.marginTop = '2px';
    subtitle.innerText = `${verdict.description} ${verdict.recommendation}`;

    textGroup.appendChild(title);
    textGroup.appendChild(subtitle);
    leftContainer.appendChild(iconBadge);
    leftContainer.appendChild(textGroup);

    const buttonGroup = document.createElement('div');
    buttonGroup.style.display = 'flex';
    buttonGroup.style.alignItems = 'center';
    buttonGroup.style.gap = '10px';

    const leaveBtn = document.createElement('button');
    leaveBtn.innerText = 'Leave Page (Safe)';
    leaveBtn.style.backgroundColor = '#E50914';
    leaveBtn.style.color = '#FFFFFF';
    leaveBtn.style.border = 'none';
    leaveBtn.style.padding = '8px 16px';
    leaveBtn.style.borderRadius = '6px';
    leaveBtn.style.fontSize = '12px';
    leaveBtn.style.fontWeight = '600';
    leaveBtn.style.cursor = 'pointer';
    leaveBtn.style.transition = 'background-color 0.2s';
    leaveBtn.onmouseover = () => leaveBtn.style.backgroundColor = '#B20710';
    leaveBtn.onmouseout = () => leaveBtn.style.backgroundColor = '#E50914';
    leaveBtn.onclick = () => {
      window.location.href = 'https://www.google.com';
    };

    const dismissBtn = document.createElement('button');
    dismissBtn.innerText = 'Dismiss';
    dismissBtn.style.backgroundColor = 'transparent';
    dismissBtn.style.color = '#A1A1AA';
    dismissBtn.style.border = '1px solid #33333D';
    dismissBtn.style.padding = '8px 14px';
    dismissBtn.style.borderRadius = '6px';
    dismissBtn.style.fontSize = '12px';
    dismissBtn.style.cursor = 'pointer';
    dismissBtn.onclick = () => {
      banner.remove();
    };

    buttonGroup.appendChild(leaveBtn);
    buttonGroup.appendChild(dismissBtn);

    banner.appendChild(leftContainer);
    banner.appendChild(buttonGroup);

    // Insert at very top
    if (document.body) {
      document.body.prepend(banner);
    } else {
      document.addEventListener('DOMContentLoaded', () => document.body.prepend(banner));
    }
  }
})();
