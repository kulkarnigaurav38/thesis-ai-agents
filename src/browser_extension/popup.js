const SERVER_URL = "http://127.0.0.1:5000";

document.addEventListener('DOMContentLoaded', refreshRequests);

async function refreshRequests() {
    try {
        const response = await fetch(`${SERVER_URL}/pending_requests?t=${Date.now()}`);
        const requests = await response.json();
        
        const container = document.getElementById('request-list');
        container.innerHTML = '';
        
        if (requests.length === 0) {
            container.innerHTML = '<div class="no-requests">No pending requests</div>';
            chrome.action.setBadgeText({ text: "" });
            return;
        }

        requests.forEach(req => {
            const card = document.createElement('div');
            card.className = 'request-card';
            card.innerHTML = `
                <div class="request-info">
                    <strong>${req.action.toUpperCase()}</strong> request<br>
                    Target: <code>${req.target}</code><br>
                    <small>${req.reason}</small>
                </div>
                <div class="btn-group">
                    <button class="btn-allow" data-id="${req.id}">Allow Once</button>
                    <button class="btn-always" data-id="${req.id}">Allow Always</button>
                    <button class="btn-deny" data-id="${req.id}">Deny</button>
                </div>
            `;
            container.appendChild(card);
        });

        // Add Listeners
        document.querySelectorAll('.btn-allow').forEach(b => 
            b.onclick = () => resolveRequest(b.dataset.id, 'PERMIT', false));
        document.querySelectorAll('.btn-always').forEach(b => 
            b.onclick = () => resolveRequest(b.dataset.id, 'PERMIT', true));
        document.querySelectorAll('.btn-deny').forEach(b => 
            b.onclick = () => resolveRequest(b.dataset.id, 'PROHIBITION', false));

    } catch (e) {
        console.error("Fetch error:", e);
        document.getElementById('request-list').innerText = "Error connecting to server.";
    }
}

async function resolveRequest(id, decision, trustAlways) {
    try {
        await fetch(`${SERVER_URL}/resolve_request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                request_id: id,
                decision: decision,
                trust_always: trustAlways
            })
        });
        
        // Refresh UI
        refreshRequests();
        
    } catch (e) {
        console.error("Resolve error:", e);
    }
}
