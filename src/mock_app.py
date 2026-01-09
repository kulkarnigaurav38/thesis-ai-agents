from flask import Flask, render_template_string, request, redirect

app = Flask(__name__)

# Template for Calendar UI
CALENDAR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Mock Calendar App</title>
    <style>
        body { font-family: sans-serif; padding: 20px; text-align: center; }
        .event { border: 1px solid #ccc; margin: 10px; padding: 10px; border-radius: 5px; }
        button { padding: 5px 10px; cursor: pointer; }
        .delete { background-color: #d9534f; color: white; border: none; }
        .view { background-color: #5bc0de; color: white; border: none; }
    </style>
</head>
<body>
    <h1>📅 My Calendar</h1>
    
    <div class="event">
        <h3>Team Meeting</h3>
        <p>10:00 AM - Room A</p>
        <!-- Extensions intercepts navigation to /api/view -->
        <a href="/api/view?id=101"><button class="view">View Details</button></a>
        <!-- Extension intercepts navigation to /api/delete -->
        <a href="/api/delete?id=101"><button class="delete">Delete Event</button></a>
    </div>

    <div class="event">
        <h3>Lunch with Client</h3>
        <p>12:30 PM - Bistro</p>
        <a href="/api/view?id=102"><button class="view">View Details</button></a>
        <a href="/api/delete?id=102"><button class="delete">Delete Event</button></a>
    </div>

    <hr>
    <h2>💸 Quick Pay</h2>
    <a href="/api/pay?amount=45&merchant=CoffeeShop"><button>Pay $45 (Safe)</button></a>
    <a href="/api/pay?amount=1000&merchant=Unknown"><button class="delete">Pay $1000 (Risky)</button></a>

</body>
</html>
"""

@app.route('/')
def home():
    return CALENDAR_HTML

@app.route('/api/view')
def view_event():
    # Policy: ALLOW view
    return "<h1>Event Details</h1><p>This is a safe action.</p><a href='/'>Back</a>"

@app.route('/api/delete')
def delete_event():
    # Policy: HITL required for delete
    return "<h1>Event Deleted!</h1><p>(If you see this, the policy failed or you approved it.)</p><a href='/'>Back</a>"

@app.route('/api/pay')
def pay():
    return f"<h1>Payment Processed</h1><p>Merchant: {request.args.get('merchant')}</p><a href='/'>Back</a>"

if __name__ == '__main__':
    print("Starting Mock App on http://localhost:8000")
    app.run(port=8000, debug=True)
