// policies.js - Policy Management UI Logic

const API_URL = "http://127.0.0.1:5000";

// Load policies on page load
document.addEventListener('DOMContentLoaded', loadPolicies);

async function loadPolicies() {
    try {
        const response = await fetch(`${API_URL}/policies`);
        const data = await response.json();
        
        renderList('whitelistItems', data.whitelist || [], 'whitelist');
        renderList('blacklistItems', data.blacklist || [], 'blacklist');
        
    } catch (error) {
        console.error('Failed to load policies:', error);
        document.getElementById('whitelistItems').innerHTML = 
            '<div class="empty">⚠️ Cannot connect to Policy Engine</div>';
        document.getElementById('blacklistItems').innerHTML = 
            '<div class="empty">⚠️ Cannot connect to Policy Engine</div>';
    }
}

function renderList(containerId, items, listType) {
    const container = document.getElementById(containerId);
    
    if (items.length === 0) {
        container.innerHTML = '<div class="empty">No entries yet</div>';
        return;
    }
    
    container.innerHTML = items.map(host => `
        <div class="list-item">
            <span>${escapeHtml(host)}</span>
            <button onclick="removeHost('${escapeHtml(host)}', '${listType}')">🗑️ Remove</button>
        </div>
    `).join('');
}

async function addHost() {
    const input = document.getElementById('hostInput');
    const select = document.getElementById('listType');
    
    let host = input.value.trim();
    const listType = select.value;
    
    if (!host) {
        showStatus('Please enter a domain', 'error');
        return;
    }
    
    // Clean up the host
    host = host.toLowerCase();
    if (host.startsWith('http://')) host = host.substring(7);
    if (host.startsWith('https://')) host = host.substring(8);
    host = host.split('/')[0]; // Remove path
    
    try {
        const response = await fetch(`${API_URL}/policies/${listType}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host })
        });
        
        if (response.ok) {
            showStatus(`Added ${host} to ${listType}`, 'success');
            input.value = '';
            loadPolicies(); // Refresh
        } else {
            const data = await response.json();
            showStatus(data.error || 'Failed to add', 'error');
        }
    } catch (error) {
        showStatus('Connection error', 'error');
    }
}

async function removeHost(host, listType) {
    if (!confirm(`Remove "${host}" from ${listType}?`)) return;
    
    try {
        const response = await fetch(`${API_URL}/policies/${listType}/${encodeURIComponent(host)}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showStatus(`Removed ${host}`, 'success');
            loadPolicies(); // Refresh
        } else {
            showStatus('Failed to remove', 'error');
        }
    } catch (error) {
        showStatus('Connection error', 'error');
    }
}

function showStatus(message, type) {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = 'status ' + type;
    
    setTimeout(() => {
        status.className = 'status';
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Handle Enter key in input
document.getElementById('hostInput')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addHost();
});
