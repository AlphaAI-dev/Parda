/**
 * Parda AI - Content Script
 * Intercepts chatbot inputs on ChatGPT, Gemini, and Claude to sanitize PII on-device,
 * and seamlessly restores tokens in incoming AI responses.
 */

(function () {
  'use strict';

  // --- Luhn Checksum ---
  function validateLuhn(numStr) {
    const clean = numStr.replace(/\D/g, '');
    if (clean.length < 13 || clean.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = clean.length - 1; i >= 0; i--) {
      let n = parseInt(clean.charAt(i), 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  // --- Verhoeff Dihedral D5 Checksum ---
  const _D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]
  ];
  const _P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
  ];
  function validateVerhoeff(str) {
    const digits = str.replace(/\D/g, '').split('').map(Number);
    if (digits.length !== 12) return false;
    let c = 0;
    const rev = [...digits].reverse();
    for (let i = 0; i < rev.length; i++) c = _D[c][_P[i % 8][rev[i]]];
    return c === 0;
  }

  // --- Detection Engine ---
  function scanText(text) {
    const matches = [];

    // Global: API Keys
    const apiRegex = /\b(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|sk-[a-zA-Z0-9]{32,64})\b/g;
    let m;
    while ((m = apiRegex.exec(text)) !== null) {
      matches.push({ type: 'API_SECRET_KEY', value: m[1], start: m.index, end: m.index + m[1].length });
    }

    // Global: Emails
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b/g;
    while ((m = emailRegex.exec(text)) !== null) {
      if (!m[0].includes('okaxis') && !m[0].includes('okhdfcbank') && !m[0].includes('paytm') && !m[0].includes('ybl')) {
        matches.push({ type: 'EMAIL_ADDRESS', value: m[0], start: m.index, end: m.index + m[0].length });
      }
    }

    // Global: Credit Cards (Luhn validated)
    const ccRegex = /\b(?:\d[ -]*?){13,19}\b/g;
    while ((m = ccRegex.exec(text)) !== null) {
      const clean = m[0].replace(/\D/g, '');
      if (clean.length >= 13 && clean.length <= 19 && validateLuhn(clean)) {
        matches.push({ type: 'CREDIT_CARD', value: m[0], start: m.index, end: m.index + m[0].length });
      }
    }

    // Global: US SSN
    const ssnRegex = /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g;
    while ((m = ssnRegex.exec(text)) !== null) {
      matches.push({ type: 'US_SSN', value: m[0], start: m.index, end: m.index + m[0].length });
    }

    // Regional: PAN Card
    const panRegex = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/gi;
    while ((m = panRegex.exec(text)) !== null) {
      matches.push({ type: 'PAN_CARD', value: m[1].toUpperCase(), start: m.index, end: m.index + m[1].length });
    }

    // Regional: Aadhaar Card (Verhoeff)
    const aadhaarRegex = /\b([2-9][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b/g;
    while ((m = aadhaarRegex.exec(text)) !== null) {
      const clean = m[1].replace(/[\s\-]/g, '');
      if (clean.length === 12 && validateVerhoeff(clean)) {
        matches.push({ type: 'AADHAAR_CARD', value: m[1], start: m.index, end: m.index + m[1].length });
      }
    }

    // Regional: UPI ID
    const upiRegex = /\b([a-zA-Z0-9._\-]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|upi|axl|apl|barodampay|federal|kotak|gpay|[a-zA-Z]{2,15}))\b/gi;
    while ((m = upiRegex.exec(text)) !== null) {
      matches.push({ type: 'UPI_ID', value: m[1], start: m.index, end: m.index + m[1].length });
    }

    // Regional: IFSC
    const ifscRegex = /\b([A-Z]{4}0[A-Z0-9]{6})\b/gi;
    while ((m = ifscRegex.exec(text)) !== null) {
      matches.push({ type: 'BANK_IFSC', value: m[1].toUpperCase(), start: m.index, end: m.index + m[1].length });
    }

    // Sort and deduplicate
    matches.sort((a, b) => a.start - b.start);
    const resolved = [];
    let lastEnd = -1;
    for (const item of matches) {
      if (item.start >= lastEnd) {
        resolved.push(item);
        lastEnd = item.end;
      }
    }
    return resolved;
  }

  function maskText(text, matches) {
    const vault = {};
    const counters = {};
    let result = '';
    let lastIdx = 0;

    matches.forEach(m => {
      result += text.substring(lastIdx, m.start);
      counters[m.type] = (counters[m.type] || 0) + 1;
      const token = `<${m.type}_${counters[m.type]}>`;
      vault[token] = m.value;
      result += token;
      lastIdx = m.end;
    });
    result += text.substring(lastIdx);
    return { masked: result, vault };
  }

  // --- UI Floating Badge ---
  let badgeEl = null;

  function createFloatingBadge() {
    if (badgeEl) return;
    badgeEl = document.createElement('div');
    badgeEl.id = 'parda-veil-badge';
    badgeEl.innerHTML = `
      <span class="parda-shield-icon">🛡️</span>
      <span class="parda-status-text">Parda Active</span>
      <span id="parda-detected-count" class="parda-pill">0</span>
    `;
    document.body.appendChild(badgeEl);
  }

  function updateBadge(count) {
    if (!badgeEl) createFloatingBadge();
    const countEl = document.getElementById('parda-detected-count');
    if (countEl) {
      countEl.innerText = count;
      badgeEl.classList.toggle('has-pii', count > 0);
    }
  }

  // --- Input Interception ---
  function attachInputListeners() {
    createFloatingBadge();

    // Check textarea or contenteditable on keyup/input
    document.addEventListener('input', (e) => {
      const target = e.target;
      if (!target) return;
      const text = target.value || target.innerText || '';
      const matches = scanText(text);
      updateBadge(matches.length);
    }, true);

    // Intercept Enter key to sanitize before transmission
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        const target = e.target;
        if (!target) return;
        const text = target.value || target.innerText || '';
        const matches = scanText(text);

        if (matches.length > 0) {
          const { masked, vault } = maskText(text, matches);

          // Update value in DOM
          if (target.value !== undefined) {
            target.value = masked;
          } else if (target.innerText !== undefined) {
            target.innerText = masked;
          }

          // Store vault mapping in background service worker
          chrome.runtime.sendMessage({
            type: 'STORE_VAULT_TOKENS',
            tokens: vault
          });

          console.log(`[Parda AI] Sanitized ${matches.length} confidential items before send.`);
          updateBadge(0);
        }
      }
    }, true);
  }

  // --- Response De-Anonymization Observer ---
  function observeResponses() {
    const observer = new MutationObserver(() => {
      // Find elements containing token patterns like <CREDIT_CARD_1> or <AADHAAR_CARD_1>
      const treeWalker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        {
          acceptNode: (node) => {
            return node.nodeValue && /<[A-Z_]+_\d+>/.test(node.nodeValue)
              ? NodeFilter.FILTER_ACCEPT
              : NodeFilter.FILTER_SKIP;
          }
        }
      );

      let node;
      while ((node = treeWalker.nextNode())) {
        const originalText = node.nodeValue;
        chrome.runtime.sendMessage(
          { type: 'RESTORE_TEXT', text: originalText },
          (response) => {
            if (response && response.restoredText && response.restoredText !== originalText) {
              node.nodeValue = response.restoredText;
            }
          }
        );
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      attachInputListeners();
      observeResponses();
    });
  } else {
    attachInputListeners();
    observeResponses();
  }
})();
