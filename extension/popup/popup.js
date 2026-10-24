document.addEventListener('DOMContentLoaded', () => {
  const shieldToggle = document.getElementById('shieldToggle');
  const deanonToggle = document.getElementById('deanonToggle');

  // Load saved state
  chrome.storage.local.get(['pardaConfig'], (result) => {
    if (result.pardaConfig) {
      shieldToggle.checked = result.pardaConfig.enabled !== false;
      deanonToggle.checked = result.pardaConfig.autoRestore !== false;
    }
  });

  // Save changes
  function save() {
    chrome.storage.local.set({
      pardaConfig: {
        enabled: shieldToggle.checked,
        autoRestore: deanonToggle.checked
      }
    });
  }

  shieldToggle.addEventListener('change', save);
  deanonToggle.addEventListener('change', save);
});
