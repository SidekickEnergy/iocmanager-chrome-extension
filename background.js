// background.js

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "enrich-ioc",
    title: "Enrich IoC with Extension",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "enrich-ioc" && info.selectionText) {
    // Save selected text for the popup to use
    chrome.storage.local.set({ selectedIoC: info.selectionText.trim() }, () => {
      // Open the popup (manually triggered by clicking extension icon)
      chrome.action.openPopup();
    });
  }
});
