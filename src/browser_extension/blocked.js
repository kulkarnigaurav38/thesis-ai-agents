const params = new URLSearchParams(window.location.search);
document.getElementById('reason').textContent = params.get('reason') || "Unknown violation";
