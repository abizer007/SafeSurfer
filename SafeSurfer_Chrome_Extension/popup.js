function updateUI(data) {
  const status = document.getElementById("status");
  const details = document.getElementById("details");

  if (data.verdict === "Bad") {
    status.textContent = "❌ Malicious Website Detected!";
    status.style.color = "red";
    details.innerHTML = `
      <p><strong>URL:</strong><br>${data.scannedUrl}</p>
      <p><strong>Confidence:</strong> ${data.confidence.toFixed(2)}%</p>
      <p><strong>Reason:</strong> ${data.reason}</p>
    `;
  } else if (data.verdict === "Good") {
    status.textContent = "✅ This site is safe.";
    status.style.color = "green";
    details.innerHTML = `<p><strong>URL:</strong><br>${data.scannedUrl}</p>`;
  } else {
    status.textContent = "⏳ Still scanning or no result...";
  }
}

function checkVerdictWithRetry(currentUrl, retries = 6) {
  chrome.storage.local.get(["verdict", "confidence", "reason", "scannedUrl"], (data) => {
    if (data && data.scannedUrl === currentUrl && data.verdict && data.confidence !== undefined) {
      updateUI(data);
    } else if (retries > 0) {
      setTimeout(() => checkVerdictWithRetry(currentUrl, retries - 1), 500);
    } else {
      const status = document.getElementById("status");
      status.textContent = "❌ Could not retrieve scan results.";
      status.style.color = "red";
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeUrl = tabs[0]?.url || '';
    checkVerdictWithRetry(activeUrl);
  });
});
