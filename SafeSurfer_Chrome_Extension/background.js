chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
    fetch("http://127.0.0.1:5001/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url, user_id: "local_user" })
    })
    .then(res => res.json())
    .then(data => {
      chrome.storage.local.set({
        verdict: data.verdict,
        confidence: data.confidence,
        reason: data.reason,
        scannedUrl: tab.url // Store the actual tab's url
      });
      console.log("SafeSurfer verdict stored:", { verdict: data.verdict, scannedUrl: tab.url });
      if (data.verdict === "Bad") {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
      } else {
        chrome.action.setBadgeText({ text: "", tabId });
      }
    })
    .catch(err => console.error("SafeSurfer API Error:", err));
  }
});
