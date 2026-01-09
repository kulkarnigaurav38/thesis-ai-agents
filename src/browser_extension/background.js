// background.js

const POLICY_SERVER_URL = "http://localhost:5000/check";
let sessionWhitelist = new Set();

// Listener for Messages (from approval UI)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "ALLOW_ONCE") {
        console.log(`[AgentEnforcer] Whitelisting session URL: ${message.url}`);
        sessionWhitelist.add(message.url);
        sendResponse({ status: "OK" });
    }
});

// Listener for Navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Ignore internal chrome pages or subframes for now (MVP)
    if (details.frameId !== 0 || details.url.startsWith("chrome://")) return;

    if (sessionWhitelist.has(details.url)) {
        console.log(`[AgentEnforcer] Allowed by Session Whitelist: ${details.url}`);
        return;
    }

    console.log(`[AgentEnforcer] Intercepting navigation to: ${details.url}`);
    
    // Determine Action based on URL (Simple Heuristics for Demo)
    let action = "navigate";
    let params = { url: details.url };

    if (details.url.includes("/api/delete")) {
        action = "delete";
        // Extract ID or context if needed
        params = { url: details.url, asset_type: "calendar_event" }; 
    } else if (details.url.includes("/api/pay")) {
        action = "pay";
    }

    try {
        const decision = await checkPolicy(action, params);
        
        if (decision.status === "DENY") {
            console.warn(`[AgentEnforcer] BLOCKED ${action} to ${details.url}. Reason: ${decision.reason}`);
            chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL("blocked.html") + `?reason=${encodeURIComponent(decision.reason)}` });
        } else if (decision.status === "HITL" || decision.status === "HITL_APPROVED") { 
            console.log("[AgentEnforcer] HITL Required. Pausing/Redirecting to approval.");
            chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL("approval.html") + `?url=${encodeURIComponent(details.url)}&reason=${encodeURIComponent(decision.reason)}` });
        } else {
            console.log(`[AgentEnforcer] ALLOWED ${action} to ${details.url}`);
        }
    } catch (error) {
        console.error("[AgentEnforcer] Error checking policy:", error);
    }
});

async function checkPolicy(action, params) {
    try {
        const response = await fetch(POLICY_SERVER_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                agent_id: "agent-007",
                tool_name: action,
                parameters: params
            })
        });
        return await response.json();
    } catch (error) {
        console.error("Failed to contact policy server:", error);
        return { status: "DENY", reason: "Policy Server Unreachable" };
    }
}
