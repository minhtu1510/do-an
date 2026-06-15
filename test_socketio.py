"""
Quick test to verify SocketIO is working
Run this and check if browser receives test events
"""

from flask import Flask, render_template_string
from flask_socketio import SocketIO
import time
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>SocketIO Test</title>
    <script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
</head>
<body>
    <h1>SocketIO Test</h1>
    <button onclick="startTest()">Start Test</button>
    <div id="messages"></div>

    <script>
        const socket = io();

        socket.on('connect', function() {
            console.log('Connected');
            addMessage('Connected to server');
        });

        socket.on('test_event', function(data) {
            console.log('Received:', data);
            addMessage('Received: ' + data.message);
        });

        function addMessage(msg) {
            const div = document.getElementById('messages');
            div.innerHTML += '<p>' + msg + '</p>';
        }

        function startTest() {
            fetch('/start-test')
                .then(r => r.json())
                .then(d => addMessage(d.message));
        }
    </script>
</body>
</html>
    ''')

@app.route('/start-test')
def start_test():
    """Start emitting test events"""
    def emit_events():
        for i in range(10):
            print(f"Emitting event {i+1}")
            socketio.emit('test_event', {'message': f'Test message {i+1}'})
            time.sleep(0.5)

    thread = threading.Thread(target=emit_events)
    thread.start()

    return {'message': 'Test started, watch for events'}

if __name__ == '__main__':
    print("Starting test server on http://127.0.0.1:5001")
    print("Open browser and click 'Start Test'")
    socketio.run(app, host='127.0.0.1', port=5001, debug=True)
