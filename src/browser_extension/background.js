// Background Service Worker

// 1. Polling for Pending Requests (Notifications)
const SERVER_URL = "http://127.0.0.1:5000";

async function checkPendingRequests() {
    try {
        const response = await fetch(`${SERVER_URL}/pending_requests?t=${Date.now()}`);
        const pending = await response.json();

        const count = pending.length;
        if (count > 0) {
            chrome.action.setBadgeText({ text: count.toString() });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
            
            // Notify for latest
            const latest = pending[0];
            chrome.notifications.create(latest.id, {
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'Agent Authorization Needed',
                message: `Agent wants to ${latest.action} on ${latest.target || 'unknown'}`,
                priority: 2
            });
        } else {
            chrome.action.setBadgeText({ text: "" });
        }
    } catch (e) {
        console.error("Polling error:", e);
    }
}

// Poll every 2 seconds
chrome.alarms.create("pollPending", { periodInMinutes: 0.05 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "pollPending") {
        checkPendingRequests();
    }
});
// 3. Navigation Interception (Redirect to Block Page)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Ignore internal pages, subframes, and our own block page
    // Also ignore when we are ALREADY redirecting (to prevent loop if logic fails)
    if (details.frameId !== 0 || 
        details.url.startsWith("chrome://") || 
        details.url.includes("chrome-extension://") ||
        details.url.includes("localhost") || 
        details.url.includes("127.0.0.1")) {
        return;
    }

    console.log("[PEP] Intercepting Navigation to:", details.url);

    // 4. Synchronous Redirect Strategy
    // We cannot "await" a server check. We must redirect immediately to ensure blocking.
    // To identify "Authorized" redirects from our own block page, we check for a token.

    if (details.url.includes("pep_pass=true")) {
        console.log("[PEP] Authorized Pass:", details.url);
        return; // Allow
    }

    // Redirect to Block Page
    const blockPageUrl = chrome.runtime.getURL("block.html");
    const redirectUrl = `${blockPageUrl}?target=${encodeURIComponent(details.url)}`;

    chrome.tabs.update(details.tabId, { url: redirectUrl });
});

// 2. Action Interception Handler (from Content Script)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "CHECK_ACTION") {
        handleActionCheck(message.data, sendResponse);
        return true; // Keep channel open for async response
    }
});

async function handleActionCheck(data, sendResponse) {
    try {
        // Call Server (Blocking Check)
        // action: "pay", target: currentUrl
        const response = await fetch(`${SERVER_URL}/check`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                agent_id: "browser_user",
                action: data.action,
                target: data.target,
                context: data.context
            })
        });

        const result = await response.json();
        
        // Notify Content Script
        sendResponse({ status: result.status });

    } catch (e) {
        console.error("Check error:", e);
        sendResponse({ status: "ERROR" });
    }
}
