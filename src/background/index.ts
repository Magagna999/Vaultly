// Minimal MV3 service worker: opens the full-page vault on first install so the user can
// complete onboarding. It never reads page content, credentials or keys.
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    void chrome.runtime.openOptionsPage();
  }
});
