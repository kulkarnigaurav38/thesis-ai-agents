// Background Service Worker - Pre-Navigation Policy Enforcement

// =============================================================================
// Configuration
// =============================================================================
const POLICY_ENGINE_URL = "http://127.0.0.1:5000";
const SHIM_URL = "http://127.0.0.1:8000";

// One-time approval tokens - auto-expire after use
// Key: URL, Value: { usesLeft: number, expires: timestamp }
const approvalTokens = new Map();

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
        // Silently ignore polling errors
    }
}

chrome.alarms.create("pollPending", { periodInMinutes: 0.05 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "pollPending") {
        checkPendingRequests();
    }
    if (alarm.name === "clearTokens") {
        // Clean up expired tokens every 5 minutes
        const now = Date.now();
        for (const [url, token] of approvalTokens.entries()) {
            if (now >= token.expires) {
                approvalTokens.delete(url);
            }
        }
        console.log("[PEP] Cleaned expired tokens");
    }
});

// Clean tokens every 5 minutes
chrome.alarms.create("clearTokens", { periodInMinutes: 5 });

// =============================================================================
// 2. Pre-Navigation Interception - BLOCK FIRST, CHECK SECOND
// =============================================================================
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only intercept main frame navigations
    if (details.frameId !== 0) return;
    
    const url = details.url;
    
    // Skip internal/extension URLs
    if (url.startsWith("chrome://") || 
        url.startsWith("chrome-extension://") ||
        url.startsWith("about:") ||
        url.startsWith("edge://") ||
        url.includes("127.0.0.1") ||
        url.includes("localhost")) {
        return;
    }
    
    // Check for valid one-time token
    const token = approvalTokens.get(url);
    if (token && token.usesLeft > 0 && Date.now() < token.expires) {
        console.log("[PEP] Using approval token for:", url);
        // Consume the token
        token.usesLeft--;
        if (token.usesLeft <= 0) {
            approvalTokens.delete(url);
            console.log("[PEP] Token consumed and removed for:", url);
        }
        return; // Allow navigation
    }
    
    // Remove expired token if any
    if (token) {
        approvalTokens.delete(url);
    }
    
    console.log("[PEP] Intercepting navigation:", url);
    
    // IMMEDIATELY redirect to checking page
    const checkingPageUrl = chrome.runtime.getURL("checking.html");
    const redirectUrl = `${checkingPageUrl}?target=${encodeURIComponent(url)}&tabId=${details.tabId}`;
    
    // Update the tab to show checking page
    chrome.tabs.update(details.tabId, { url: redirectUrl });
});

// =============================================================================
// 3. Handle messages from checking page
// =============================================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "APPROVED_URL") {
        // Add one-time token (expires in 10 seconds, 1 use only)
        approvalTokens.set(message.url, {
            usesLeft: 1,
            expires: Date.now() + 10000 // 10 second window
        });
        console.log("[PEP] One-time token created for:", message.url);
        sendResponse({ success: true });
    }
    
    if (message.type === "TRUST_ALWAYS") {
        // For "Trust Always" - give more uses for this session
        approvalTokens.set(message.url, {
            usesLeft: 100, // Effectively unlimited for session
            expires: Date.now() + (30 * 60 * 1000) // 30 minutes
        });
        console.log("[PEP] Trust token created for:", message.url);
        sendResponse({ success: true });
    }
    
    if (message.type === "CHECK_ACTION") {
        handleActionCheck(message.data, sendResponse);
        return true;
    }
});

// =============================================================================
// 4. Action Interception Handler (from Content Script)
// =============================================================================
async function handleActionCheck(data, sendResponse) {
    try {
        const response = await fetch(`${SHIM_URL}/authorize`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                protocol: "BROWSER",
                payload: {
                    url: data.target,
                    tab_id: data.context?.tab_id || "unknown",
                    action_type: data.action
                }
            })
        });

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

console.log("[PEP] Background service worker started - Pre-navigation mode with one-time tokens");
