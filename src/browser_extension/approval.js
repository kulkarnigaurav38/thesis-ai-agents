const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('url');
document.getElementById('url').textContent = targetUrl;
document.getElementById('reason').textContent = params.get('reason');

// Allow Once: Tell background to whitelist this URL for this session
document.getElementById('approve-once').onclick = () => {
    chrome.runtime.sendMessage({ action: "ALLOW_ONCE", url: targetUrl }, (response) => {
        window.location.href = targetUrl;
    });
};

// Allow Always: Tell Server to add to trusted Host list
document.getElementById('approve-always').onclick = async () => {
    try {
        // Extract Host from URL
        const urlObj = new URL(targetUrl);
        const host = urlObj.hostname;

        const response = await fetch("http://localhost:5000/trust", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                category: "host",
                value: host
            })
        });
        
        if (response.ok) {
            window.location.href = targetUrl;
        } else {
            alert("Failed to update policy server.");
        }
    } catch (e) {
        console.error(e);
        alert("Error contacting policy server.");
    }
};

document.getElementById('deny').onclick = () => {
    window.close(); // Or navigate to blank
};
