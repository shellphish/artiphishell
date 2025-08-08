// WebSocket connection management
let ws = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY = 5000; // 5 seconds
let reconnectTimeout = null;

export { ws };

export function resetReconnectAttempts() {
    reconnectAttempts = 0;
}

export function connectWebSocket() {
    // Clear any existing reconnection timeout
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }

    // Don't try to connect if we've exceeded max attempts
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error('Max reconnection attempts reached');
        updateConnectionStatus(false, 'Connection failed after multiple attempts');
        return;
    }

    const clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${clientId}`;
    console.log("Attempting to connect to:", wsUrl);

    try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('Connected to pipeline');
            reconnectAttempts = 0; // Reset reconnect attempts on successful connection
            updateConnectionStatus(true);
            document.querySelector('.loading').style.display = 'none';
        };

        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                handleMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateConnectionStatus(false, 'Connection error occurred');
        };

        ws.onclose = (event) => {
            console.log('Disconnected from pipeline:', event.code, event.reason);
            let errorMessage = 'Disconnected from server';
            
            // Add more specific error messages based on close code
            switch (event.code) {
                case 1000: errorMessage = 'Connection closed normally'; break;
                case 1001: errorMessage = 'Server is going away'; break;
                case 1002: errorMessage = 'Protocol error'; break;
                case 1003: errorMessage = 'Unsupported data'; break;
                case 1005: errorMessage = 'No status received'; break;
                case 1006: errorMessage = 'Connection closed abnormally'; break;
                case 1007: errorMessage = 'Invalid frame payload data'; break;
                case 1008: errorMessage = 'Policy violation'; break;
                case 1009: errorMessage = 'Message too big'; break;
                case 1010: errorMessage = 'Missing extension'; break;
                case 1011: errorMessage = 'Internal server error'; break;
                case 1012: errorMessage = 'Service restart'; break;
                case 1013: errorMessage = 'Try again later'; break;
                case 1014: errorMessage = 'Bad gateway'; break;
                case 1015: errorMessage = 'TLS handshake failed'; break;
            }
            
            updateConnectionStatus(false, errorMessage);
            
            // Only attempt to reconnect if the page is visible
            if (document.visibilityState === 'visible') {
                reconnectAttempts++;
                const delay = Math.min(RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts - 1), 30000); // Max 30 second delay
                console.log(`Attempting to reconnect in ${delay/1000} seconds (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`);
                reconnectTimeout = setTimeout(connectWebSocket, delay);
            }
        };
    } catch (error) {
        console.error('Error creating WebSocket connection:', error);
        updateConnectionStatus(false, 'Failed to create connection');
        reconnectAttempts++;
        reconnectTimeout = setTimeout(connectWebSocket, RECONNECT_DELAY);
    }
}

function handleMessage(message) {
    const event = new CustomEvent('websocketMessage', { detail: message });
    document.dispatchEvent(event);
}

export function sendMessage(message) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
    }
}

export function closeWebSocket() {
    if (ws) {
        ws.close();
    }
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }
}

function updateConnectionStatus(connected, message = '') {
    const statusDot = document.querySelector('.connection-dot');
    const statusText = document.querySelector('.connection-text');

    if (connected) {
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';
    } else {
        statusDot.classList.remove('connected');
        statusText.textContent = message || 'Disconnected';
    }
} 