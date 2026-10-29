// CyberWatch Background Service Worker (Manifest V3)
// Privacy-First: No automatic background surveillance, no tracking, no history collection.

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'GET_ACTIVE_TAB') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs && tabs[0];
      if (activeTab && activeTab.url) {
        sendResponse({
          success: true,
          url: activeTab.url,
          title: activeTab.title || '',
        });
      } else {
        sendResponse({
          success: false,
          error: 'No accessible active tab found.',
        });
      }
    });
    return true; // Keep message channel open for async response
  }

  if (message.action === 'OPEN_REPORT') {
    const reportUrl = message.url;
    if (reportUrl && (reportUrl.startsWith('http://') || reportUrl.startsWith('https://'))) {
      chrome.tabs.create({ url: reportUrl });
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false, error: 'Invalid URL scheme.' });
    }
    return false;
  }

  return false;
});

console.log('[CyberWatch] Service worker initialized safely in MV3.');
