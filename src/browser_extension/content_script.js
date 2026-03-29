// Content Script - Intercepts "Buy" / "Pay" Buttons

document.addEventListener("click", (event) => {
    const target = event.target;
    
    // 1. Heuristic Detection
    // Check if element is a button or input[type=submit] or inside a button
    const clickable = target.closest("button, a, input[type='submit']");
    
    if (clickable) {
        const text = (clickable.innerText || clickable.value || "").toLowerCase();
        const sensitiveKeywords = ["buy", "pay now", "checkout", "place order", "complete purchase"];
        
        const isSensitive = sensitiveKeywords.some(kw => text.includes(kw));
        
        if (isSensitive) {
            // 2. Intercept
            console.log("[PEP] Intercepted Sensitive Action:", text);
            event.preventDefault();
            event.stopPropagation();
            
            // 3. Ask Background to Check Policy
            chrome.runtime.sendMessage({
                type: "CHECK_ACTION",
                data: {
                    action: "pay",
                    target: window.location.hostname,
                    context: { text: text, url: window.location.href }
                }
            }, (response) => {
                console.log("[PEP] Policy Verdict:", response);
                
                if (response && response.status === "PERMIT") {
                    // 4. Resume Action (Re-click without interception)
                    // We need to bypass our own listener. 
                    // Simple way: create a new event or Temporarily remove listener? 
                    // Better: The user has to click AGAIN? No, that's bad UX.
                    // Implementation: We can't easily re-trigger the exact event trustedly in all cases.
                    // For prototype: Alert user "Approved! Please click again." or try `clickable.click()` logic.
                    // If we call .click(), it might trigger this listener again.
                    // Let's add a dataset flag to ignore next click.
                    
                    clickable.dataset.pepVerified = "true";
                    clickable.click(); // Should recurse
                } else {
                    alert("Agent Action Blocked by Policy.");
                }
            });
            
            return false;
        }
    }
    
    // Check for re-entrancy
    if (target.dataset && target.dataset.pepVerified === "true") {
        // Reset and allow
        target.dataset.pepVerified = "false";
        return; 
    }
}, true); // Capture phase
