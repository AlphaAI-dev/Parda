/**
 * Parda AI - Background Service Worker
 * Manages ephemeral in-memory token vaults for active chat sessions.
 */

// In-memory session vault: maps token -> original secret (never saved to disk or network)
const sessionVault = new Map();

// Configuration defaults
const DEFAULT_CONFIG = {
  enabled: true,
  strategy: 'TOKEN', // 'TOKEN', 'BLACKOUT', 'SYNTHETIC'
  scope: 'ALL',      // 'ALL', 'GLOBAL', 'REGIONAL'
  autoRestore: true
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['pardaConfig'], (result) => {
    if (!result.pardaConfig) {
      chrome.storage.local.set({ pardaConfig: DEFAULT_CONFIG });
    }
  });
  console.log('[Parda AI] Background privacy engine initialized.');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'STORE_VAULT_TOKENS') {
    // Store tokens into ephemeral memory
    if (request.tokens && typeof request.tokens === 'object') {
      for (const [token, orig] of Object.entries(request.tokens)) {
        sessionVault.set(token, orig);
      }
    }
    sendResponse({ status: 'OK', count: sessionVault.size });
    return true;
  }

  if (request.type === 'RESTORE_TEXT') {
    // Re-hydrate tokens from in-memory vault
    let text = request.text || '';
    for (const [token, orig] of sessionVault.entries()) {
      if (text.includes(token)) {
        text = text.split(token).join(orig);
      }
    }
    sendResponse({ restoredText: text });
    return true;
  }

  if (request.type === 'CLEAR_VAULT') {
    sessionVault.clear();
    sendResponse({ status: 'CLEARED' });
    return true;
  }
});
