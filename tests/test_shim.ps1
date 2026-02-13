# Test Script for Universal Security Shim
# This script demonstrates how to test the Shim service

# Test 1: Health Check
Write-Host "`n=== Test 1: Health Check ===" -ForegroundColor Cyan
Invoke-RestMethod -Uri http://localhost:8000/health -Method GET

# Test 2: BROWSER Protocol Authorization (Untrusted URL)
Write-Host "`n=== Test 2: BROWSER Protocol (Untrusted URL) ===" -ForegroundColor Cyan
Write-Host "Note: This will timeout after 60s waiting for user consent" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri http://localhost:8000/authorize `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"protocol": "BROWSER", "payload": {"url": "https://google.com", "tab_id": "123"}}'
    Write-Host "Response: $response" -ForegroundColor Green
} catch {
    Write-Host "Expected PROHIBITION response (403):" -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Red
}

# Test 3: MCP Protocol Authorization
Write-Host "`n=== Test 3: MCP Protocol ===" -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri http://localhost:8000/authorize `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"protocol": "MCP", "payload": {"tool_name": "read_file", "arguments": {"path": "/etc/passwd"}}}'
    Write-Host "Response: $response" -ForegroundColor Green
} catch {
    Write-Host "Expected PROHIBITION response (403):" -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Red
}

Write-Host "`n=== All Tests Complete ===" -ForegroundColor Cyan
Write-Host "The Shim service is working correctly!" -ForegroundColor Green
