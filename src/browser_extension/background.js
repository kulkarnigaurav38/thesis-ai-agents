// Background Service Worker

// =============================================================================
// Configuration
// =============================================================================
const POLICY_ENGINE_URL = "http://127.0.0.1:5000";  // For polling pending requests
const SHIM_URL = "http://127.0.0.1:8000";           // Universal Security Shim

// =============================================================================
// 1. Polling for Pending Requests (Notifications)
// =============================================================================
async function checkPendingRequests() {
    try {
        const response = await fetch(`${POLICY_ENGINE_URL}/pending_requests?t=${Date.now()}`);
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

// =============================================================================
// 2. Navigation Interception via Universal Security Shim
// =============================================================================
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Ignore internal pages, subframes, and our own block page
    if (details.frameId !== 0 || 
        details.url.startsWith("chrome://") || 
        details.url.includes("chrome-extension://") ||
        details.url.includes("localhost") || 
        details.url.includes("127.0.0.1")) {
        return;
    }

    console.log("[PEP] Intercepting Navigation to:", details.url);

    // Call Universal Security Shim with BROWSER protocol
    // The Shim normalizes the intent and forwards to Policy Engine
    fetch(`${SHIM_URL}/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            protocol: "BROWSER",
            payload: {
                url: details.url,
                tab_id: String(details.tabId)
            }
        })
    }).then(res => {
        // Shim returns 200 for PERMIT, 403 for PROHIBITION
        if (res.status === 403) {
            // Blocked - redirect to block page
            console.log("[PEP] Blocked:", details.url);
            const blockPageUrl = chrome.runtime.getURL("blocked.html");
            const redirectUrl = `${blockPageUrl}?target=${encodeURIComponent(details.url)}`;
            chrome.tabs.update(details.tabId, { url: redirectUrl });
        } else if (res.status === 200) {
            // Permitted - allow navigation
            console.log("[PEP] Permitted:", details.url);
        } else {
            // Unexpected status - treat as error, allow but log
            console.warn("[PEP] Unexpected response status:", res.status);
        }
    }).catch(err => {
        console.error("[PEP] Shim Error:", err);
        // On error, fail-safe: block the navigation
        const blockPageUrl = chrome.runtime.getURL("blocked.html");
        const redirectUrl = `${blockPageUrl}?target=${encodeURIComponent(details.url)}&reason=shim_error`;
        chrome.tabs.update(details.tabId, { url: redirectUrl });
    });
});

// =============================================================================
// 3. Action Interception Handler (from Content Script)
// =============================================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "CHECK_ACTION") {
        handleActionCheck(message.data, sendResponse);
        return true; // Keep channel open for async response
    }
});

async function handleActionCheck(data, sendResponse) {
    try {
        // Call Shim with BROWSER protocol for action checks
        // Actions like "pay" are still BROWSER protocol but with different action types
        const response = await fetch(`${SHIM_URL}/authorize`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                protocol: "BROWSER",
                payload: {
                    url: data.target,
                    tab_id: data.context?.tab_id || "unknown",
                    action_type: data.action  // Additional context for non-navigation actions
                }
            })
        });

        // Map HTTP status to result
        if (response.status === 200) {
            sendResponse({ status: "PERMIT" });
        } else if (response.status === 403) {
            sendResponse({ status: "PROHIBITION" });
        } else {
            sendResponse({ status: "ERROR" });
        }

    } catch (e) {
        console.error("[PEP] Action Check Error:", e);
        sendResponse({ status: "ERROR" });
    }
}
