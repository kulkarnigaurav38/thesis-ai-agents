// checking.js - Policy check page logic

const SHIM_URL = "http://127.0.0.1:8000";

// Get target URL from query params
const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('target');
const tabId = params.get('tabId');

document.getElementById('targetUrl').textContent = targetUrl || 'Unknown URL';

async function checkPolicy() {
    if (!targetUrl) {
        showResult('block', 'No target URL specified', false);
        return;
    }

    try {
        document.getElementById('status').textContent = 'Checking with Security Shim...';
        
        const response = await fetch(`${SHIM_URL}/authorize`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                protocol: 'BROWSER',
                payload: {
                    url: targetUrl,
                    tab_id: tabId || 'checking'
                }
            })
        });

        const data = await response.json();
        
        if (response.status === 200) {
            // PERMITTED - notify background, then redirect
            document.getElementById('status').textContent = '✅ Permitted! Redirecting...';
            document.getElementById('spinner').style.borderTopColor = '#28a745';
            
            // MUST notify background script BEFORE redirecting
            chrome.runtime.sendMessage({ type: "APPROVED_URL", url: targetUrl }, () => {
                // Small delay to ensure message is processed
                setTimeout(() => {
                    window.location.href = targetUrl;
                }, 100);
            });
            
        } else if (response.status === 403) {
            // BLOCKED
            const reason = data.reason || 'Policy violation';
            
            if (reason.includes('consent') || reason.includes('Consent')) {
                // Needs user consent
                showResult('consent', `⚠️ This site requires your approval:\n${reason}`, true);
            } else {
                // Explicitly blocked
                showResult('block', `🚫 Access Denied:\n${reason}`, false);
            }
        } else {
            showResult('block', `Unexpected response: ${response.status}`, false);
        }
        
    } catch (error) {
        console.error('Policy check error:', error);
        showResult('block', `❌ Cannot reach Security Shim:\n${error.message}`, false);
    }
}

function showResult(type, message, showConsentButtons) {
    document.getElementById('spinner').style.display = 'none';
    document.getElementById('status').style.display = 'none';
    
    const resultDiv = document.getElementById('result');
    resultDiv.className = 'result ' + type;
    resultDiv.style.display = 'block';
    
    document.getElementById('resultMessage').textContent = message;
    
    const buttonsDiv = document.getElementById('buttons');
    buttonsDiv.innerHTML = '';
    
    if (showConsentButtons) {
        // User can approve or deny
        const allowBtn = document.createElement('button');
        allowBtn.className = 'btn btn-allow';
        allowBtn.textContent = '✓ Allow This Time';
        allowBtn.onclick = () => allowNavigation();
        
        const allowAlwaysBtn = document.createElement('button');
        allowAlwaysBtn.className = 'btn btn-allow';
        allowAlwaysBtn.textContent = '✓ Trust Always';
        allowAlwaysBtn.onclick = () => trustAndAllow();
        
        const denyBtn = document.createElement('button');
        denyBtn.className = 'btn btn-deny';
        denyBtn.textContent = '✗ Block';
        denyBtn.onclick = () => goBack();
        
        buttonsDiv.appendChild(allowBtn);
        buttonsDiv.appendChild(allowAlwaysBtn);
        buttonsDiv.appendChild(denyBtn);
    } else {
        // Just show back button
        const backBtn = document.createElement('button');
        backBtn.className = 'btn btn-back';
        backBtn.textContent = '← Go Back';
        backBtn.onclick = () => goBack();
        buttonsDiv.appendChild(backBtn);
    }
}

function allowNavigation() {
    // Notify background script, then proceed
    chrome.runtime.sendMessage({ type: "APPROVED_URL", url: targetUrl }, () => {
        window.location.href = targetUrl;
    });
}

async function trustAndAllow() {
    // Add to trusted hosts via Policy Engine
    try {
        const host = new URL(targetUrl).hostname;
        await fetch('http://127.0.0.1:5000/trust', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                category: 'host',
                value: host
            })
        });
    } catch (e) {
        console.error('Failed to add trust:', e);
    }
    
    // Use TRUST_ALWAYS for permanent session trust
    chrome.runtime.sendMessage({ type: "TRUST_ALWAYS", url: targetUrl }, () => {
        window.location.href = targetUrl;
    });
}

function goBack() {
    if (window.history.length > 1) {
        window.history.back();
    } else {
        window.close();
    }
}

// Start policy check
checkPolicy();
