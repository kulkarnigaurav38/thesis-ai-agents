const SERVER_URL = "http://127.0.0.1:5000";

async function performCheck() {
    // 1. Get Target from URL params
    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get('target');
    
    if (!targetUrl) {
        document.getElementById('status-text').innerText = "No target URL provided.";
        return;
    }

    document.getElementById('target').innerText = targetUrl;

    try {
        // 2. Call Server (Blocking)
        // This will hang if CONSENT_NEEDED until user resolves it in Popup
        const response = await fetch(`${SERVER_URL}/check`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                agent_id: "browser_user",
                action: "navigate", // Only nav goes to block page
                target: targetUrl
            })
        });

        const result = await response.json();
        console.log("Verdict:", result);

        // 3. Handle Verdict
        if (result.status === "PERMIT") {
            document.getElementById('title').innerText = "Access Granted";
            document.getElementById('status-text').innerText = "Redirecting you now...";
            document.getElementById('spinner').style.borderTopColor = "#2ecc71"; // Green
            
            // Wait a split second for UX then redirect
            setTimeout(() => {
                window.location.replace(targetUrl);
            }, 500);

        } else if (result.status === "PROHIBITION") {
            document.getElementById('title').innerText = "Access Denied";
            document.getElementById('status-text').innerText = "Policy Engine blocked this request.";
            document.getElementById('spinner').style.display = "none";
            document.getElementById('error-msg').style.display = "block";
            document.getElementById('error-msg').innerText = result.reason || "Generic Prohibition";
        }

    } catch (e) {
        console.error(e);
        document.getElementById('title').innerText = "Connection Error";
        document.getElementById('status-text').innerText = "Could not reach Policy Server.";
        document.getElementById('spinner').style.display = "none";
    }
}

document.addEventListener('DOMContentLoaded', performCheck);
